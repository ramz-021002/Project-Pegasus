"""
Celery application configuration and task orchestration.
Manages the analysis workflow for malware samples.
"""
import logging
from celery import Celery, chain, group
from celery.signals import task_prerun, task_postrun
from pathlib import Path
import tempfile
import uuid

from app.config import settings
from app.database import SessionLocal, DatabaseOperations, SampleStatus, AnalysisStatus, AnalysisType
from app.services.docker_manager import docker_manager
from app.services.file_handler import file_handler

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    'pegasus',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend
)

# Celery configuration
celery_app.conf.update(
    task_track_started=settings.celery_task_track_started,
    task_time_limit=settings.celery_task_time_limit,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)


@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Log when task starts."""
    logger.info(f"Task {task.name} [{task_id}] starting with args={args}, kwargs={kwargs}")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **extra):
    """Log when task completes."""
    logger.info(f"Task {task.name} [{task_id}] completed with state={state}")


@celery_app.task(name='pegasus.analyze_sample', bind=True)
def analyze_sample(self, sample_id: str):
    """
    Orchestrate complete analysis of a malware sample.
    Chains together static, dynamic, and network analysis.

    Args:
        sample_id: UUID of the sample to analyze
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting analysis orchestration for sample {sample_id}")

        # Get sample from database
        sample = DatabaseOperations.get_sample_by_id(db, uuid.UUID(sample_id))
        if not sample:
            logger.error(f"Sample not found: {sample_id}")
            return {"error": "Sample not found"}

        # Update sample status
        DatabaseOperations.update_sample_status(db, uuid.UUID(sample_id), SampleStatus.ANALYZING)

        # Build quarantine path (use stored encryption_key_id, fall back to sample id)
        key_id = getattr(sample, 'encryption_key_id', None) or str(sample.id)
        quarantine_path = settings.upload_dir / f"{key_id}.encrypted"

        # Create workflow: static -> dynamic -> network (parallel dynamic+network)
        workflow = chain(
            run_static_analysis.s(sample_id, str(quarantine_path)),
            group(
                run_dynamic_analysis.s(sample_id, str(quarantine_path)),
                # Network analysis is integrated into dynamic analysis
            )
        )

        # Execute workflow
        result = workflow.apply_async()

        logger.info(f"Analysis workflow started for sample {sample_id}")
        return {"sample_id": sample_id, "workflow_id": result.id}

    except Exception as e:
        logger.error(f"Failed to orchestrate analysis: {e}", exc_info=True)
        # Update sample status to failed
        try:
            DatabaseOperations.update_sample_status(db, uuid.UUID(sample_id), SampleStatus.FAILED)
        except:
            pass
        return {"error": str(e)}

    finally:
        db.close()


@celery_app.task(name='pegasus.run_static_analysis', bind=True)
def run_static_analysis(self, sample_id: str, quarantine_path: str):
    """
    Run static analysis on a malware sample.

    Args:
        sample_id: UUID of the sample
        quarantine_path: Path to encrypted sample file

    Returns:
        Analysis results dictionary
    """
    db = SessionLocal()
    analysis_result_id = None

    try:
        logger.info(f"Starting static analysis for sample {sample_id}")

        # Create analysis result record
        analysis_result = DatabaseOperations.create_analysis_result(
            db=db,
            sample_id=uuid.UUID(sample_id),
            analysis_type=AnalysisType.STATIC,
            status=AnalysisStatus.RUNNING
        )
        analysis_result_id = analysis_result.id

        # Decrypt sample to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as temp_file:
            temp_path = Path(temp_file.name)

        # Ensure quarantined file exists before attempting to decrypt
        qp = Path(quarantine_path)
        if not qp.exists():
            raise FileNotFoundError(f"Quarantined file not found: {qp}")

        file_handler.decrypt_file(qp, temp_path)

        # Run static analysis in Docker container
        success, results, container_id = docker_manager.run_static_analysis(
            temp_path,
            timeout=settings.analysis_timeout
        )

        # Update analysis result
        DatabaseOperations.update_analysis_result(
            db=db,
            result_id=analysis_result_id,
            status=AnalysisStatus.COMPLETED if success else AnalysisStatus.FAILED,
            results_json=results,
            error_message=results.get('error') if not success else None
        )

        # Store network indicators if found
        if success and 'indicators' in results:
            from app.database import IndicatorType, NetworkIndicator
            for indicator in results['indicators']:
                try:
                    indicator_type = IndicatorType[indicator['type'].upper()]
                    DatabaseOperations.create_network_indicator(
                        db=db,
                        sample_id=uuid.UUID(sample_id),
                        indicator_type=indicator_type,
                        value=indicator['value'],
                        context='static_analysis'
                    )
                except Exception as e:
                    logger.warning(f"Failed to store indicator: {e}")

        # Clean up temporary file
        temp_path.unlink(missing_ok=True)

        logger.info(f"Static analysis completed for sample {sample_id}")
        return {"success": success, "results": results}

    except Exception as e:
        logger.error(f"Static analysis failed: {e}", exc_info=True)

        # Update analysis result to failed
        if analysis_result_id:
            try:
                DatabaseOperations.update_analysis_result(
                    db=db,
                    result_id=analysis_result_id,
                    status=AnalysisStatus.FAILED,
                    error_message=str(e)
                )
            except:
                pass

        return {"success": False, "error": str(e)}

    finally:
        db.close()


@celery_app.task(name='pegasus.run_dynamic_analysis', bind=True)
def run_dynamic_analysis(self, static_results, sample_id: str, quarantine_path: str):
    """
    Run dynamic analysis on a malware sample.

    Args:
        static_results: Results from static analysis (from chain)
        sample_id: UUID of the sample
        quarantine_path: Path to encrypted sample file

    Returns:
        Analysis results dictionary
    """
    db = SessionLocal()
    analysis_result_id = None
    network_id = None

    try:
        logger.info(f"Starting dynamic analysis for sample {sample_id}")

        # Get sample info for original filename
        sample = DatabaseOperations.get_sample_by_id(db, uuid.UUID(sample_id))
        original_filename = sample.original_filename if sample else 'sample.bin'

        # Create analysis result record
        analysis_result = DatabaseOperations.create_analysis_result(
            db=db,
            sample_id=uuid.UUID(sample_id),
            analysis_type=AnalysisType.DYNAMIC,
            status=AnalysisStatus.RUNNING
        )
        analysis_result_id = analysis_result.id

        # Create isolated network
        network_id = docker_manager.create_isolated_network()

        # Start network gateway
        gateway_success, gateway_container_id = docker_manager.run_network_gateway(
            network_id,
            duration=settings.dynamic_execution_timeout + 30
        )

        if not gateway_success:
            raise Exception("Failed to start network gateway")

        # Decrypt sample to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as temp_file:
            temp_path = Path(temp_file.name)

        # Ensure quarantined file exists before attempting to decrypt
        qp = Path(quarantine_path)
        if not qp.exists():
            raise FileNotFoundError(f"Quarantined file not found: {qp}")

        file_handler.decrypt_file(qp, temp_path)

        # Run dynamic analysis in Docker container
        success, results, container_id = docker_manager.run_dynamic_analysis(
            temp_path,
            network_id,
            timeout=settings.analysis_timeout,
            original_filename=original_filename
        )

        # Stop and get logs from gateway
        if gateway_container_id and gateway_container_id != "none":
            docker_manager.stop_container(gateway_container_id)
            gateway_logs = docker_manager.get_container_logs(gateway_container_id)
            if gateway_logs:
                results['network_logs'] = gateway_logs[:10000]  # Limit log size
            docker_manager.cleanup_container(gateway_container_id)

        # Update analysis result
        DatabaseOperations.update_analysis_result(
            db=db,
            result_id=analysis_result_id,
            status=AnalysisStatus.COMPLETED if success else AnalysisStatus.FAILED,
            results_json=results,
            error_message=results.get('error') if not success else None
        )

        # Store network indicators from dynamic analysis
        if success and 'network_connections' in results:
            from app.database import IndicatorType, NetworkIndicator
            for conn in results['network_connections']:
                try:
                    # Store IP addresses
                    if 'dst_ip' in conn and conn['dst_ip'] != '127.0.0.1':
                        DatabaseOperations.create_network_indicator(
                            db=db,
                            sample_id=uuid.UUID(sample_id),
                            indicator_type=IndicatorType.IP,
                            value=conn['dst_ip'],
                            context=f"dynamic_analysis:{conn.get('protocol', 'unknown')}"
                        )
                except Exception as e:
                    logger.warning(f"Failed to store network indicator: {e}")

        # Clean up temporary file
        temp_path.unlink(missing_ok=True)

        # Update sample status to completed
        DatabaseOperations.update_sample_status(db, uuid.UUID(sample_id), SampleStatus.COMPLETED)

        logger.info(f"Dynamic analysis completed for sample {sample_id}")
        return {"success": success, "results": results}

    except Exception as e:
        logger.error(f"Dynamic analysis failed: {e}", exc_info=True)

        # Update analysis result to failed
        if analysis_result_id:
            try:
                DatabaseOperations.update_analysis_result(
                    db=db,
                    result_id=analysis_result_id,
                    status=AnalysisStatus.FAILED,
                    error_message=str(e)
                )
            except:
                pass

        # Update sample status to failed
        try:
            DatabaseOperations.update_sample_status(db, uuid.UUID(sample_id), SampleStatus.FAILED)
        except:
            pass

        return {"success": False, "error": str(e)}

    finally:
        # Clean up network
        if network_id:
            docker_manager.remove_network(network_id)

        db.close()


@celery_app.task(name='pegasus.cleanup_orphaned_resources')
def cleanup_orphaned_resources():
    """
    Periodic task to clean up orphaned Docker containers and networks.
    Should be run periodically via Celery beat.
    """
    logger.info("Running orphaned resource cleanup")

    containers_cleaned = docker_manager.cleanup_orphaned_containers()
    networks_cleaned = docker_manager.cleanup_orphaned_networks()

    logger.info(f"Cleanup complete: {containers_cleaned} containers, {networks_cleaned} networks")

    return {
        "containers_cleaned": containers_cleaned,
        "networks_cleaned": networks_cleaned
    }
