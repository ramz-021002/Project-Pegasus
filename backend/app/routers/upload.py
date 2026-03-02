"""
File upload router for malware sample submission.
Handles file uploads, validation, and analysis initiation.
"""

import logging
import tempfile
from pathlib import Path
from typing import Any, Dict

from fastapi import (
    APIRouter,
    UploadFile,
    File,
    Depends,
    HTTPException,
    status,
    Form,
    Query,
)
from sqlalchemy.orm import Session

from app.database import get_db, Sample, SampleStatus, DatabaseOperations
from app.services.file_handler import file_handler
from app.services.zip_utils import zip_extractor
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", status_code=status.HTTP_201_CREATED)
async def upload_sample(
    file: UploadFile = File(..., description="Malware sample file"),
    password: str = Form(None, description="Password for zip file (if applicable)"),
    reanalyze: bool = Form(
        False, description="Re-analyze and overwrite if sample exists"
    ),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Upload a malware sample for analysis.

    Args:
        file: Uploaded file
        db: Database session

    Returns:
        Sample metadata and status

    Raises:
        HTTPException: If file validation fails or processing error occurs
    """
    logger.info(f"Receiving upload: {file.filename}")

    # Validate filename
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required"
        )

    # Create temporary file for initial processing
    temp_file = None
    extracted_file = None
    try:
        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_file = Path(temp.name)
            content = await file.read()
            temp.write(content)

        logger.info(f"Saved temporary file: {temp_file}")

        # Check if it's a zip file
        file_type = file_handler.get_file_type(temp_file)
        is_zip = file_type == "application/zip" or temp_file.suffix.lower() == ".zip"

        if is_zip:
            try:
                extracted_file = zip_extractor.extract_zip(temp_file, password)
                logger.info(f"Extracted file from zip: {extracted_file}")
            except Exception as e:
                logger.error(f"Failed to extract zip: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to extract zip: {str(e)}",
                )
            process_file = extracted_file
            process_filename = extracted_file.name
        else:
            process_file = temp_file
            process_filename = file.filename

        # Validate file
        is_valid, error_message = file_handler.validate_file(
            process_file, process_filename
        )
        if not is_valid:
            logger.warning(f"File validation failed: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=error_message
            )

        # Get file information and hashes
        file_info = file_handler.get_file_info(process_file)
        logger.info(f"File SHA256: {file_info['sha256']}")

        # Check if sample already exists
        existing_sample = DatabaseOperations.get_sample_by_sha256(
            db, file_info["sha256"]
        )
        if existing_sample:
            logger.info(f"Sample already exists: {existing_sample.id}")
            if not reanalyze:
                return {
                    "message": "Sample already exists. Set reanalyze=true to overwrite.",
                    "sample_id": str(existing_sample.id),
                    "sha256": existing_sample.sha256,
                    "status": existing_sample.status.value,
                    "upload_timestamp": existing_sample.upload_timestamp.isoformat(),
                    "can_reanalyze": True,
                }
            # Overwrite: update status and trigger re-analysis
            existing_sample.status = SampleStatus.PENDING
            db.commit()
            from app.tasks.orchestration import analyze_sample

            analyze_sample.delay(str(existing_sample.id))
            return {
                "message": "Sample re-analysis started. Previous results will be overwritten.",
                "sample_id": str(existing_sample.id),
                "sha256": existing_sample.sha256,
                "status": existing_sample.status.value,
                "upload_timestamp": existing_sample.upload_timestamp.isoformat(),
                "reanalyze": True,
            }

        # Quarantine and encrypt file
        quarantine_path, encryption_key_id, hashes = file_handler.quarantine_file(
            process_file, process_filename
        )

        # Create database record
        sample = DatabaseOperations.create_sample(
            db=db,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_size=file_info["file_size"],
            file_type=file_info["file_type"],
            original_filename=process_filename,
            encryption_key_id=encryption_key_id,
            status=SampleStatus.PENDING,
        )

        logger.info(f"Sample created: {sample.id}")

        # Trigger Celery task for analysis
        from app.tasks.orchestration import analyze_sample

        analyze_sample.delay(str(sample.id))

        return {
            "message": "Sample uploaded successfully",
            "sample_id": str(sample.id),
            "sha256": sample.sha256,
            "md5": sample.md5,
            "sha1": sample.sha1,
            "file_size": sample.file_size,
            "file_type": sample.file_type,
            "original_filename": sample.original_filename,
            "status": sample.status.value,
            "upload_timestamp": sample.upload_timestamp.isoformat(),
        }

    except HTTPException:
        # Re-raise HTTP exceptions
        raise

    except Exception as e:
        logger.error(f"Error processing upload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing upload: {str(e)}",
        )

    finally:
        # Clean up temporary and extracted files
        try:
            if temp_file and temp_file.exists():
                temp_file.unlink()
            if extracted_file and extracted_file.exists():
                extracted_file.unlink()
        except Exception as e:
            logger.error(f"Error cleaning up temporary file: {e}")


@router.get("/{sample_id}")
async def get_sample_status(
    sample_id: str, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get status of a malware sample analysis.
    """
    try:
        import uuid

        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found"
        )

    # Get analysis results
    analysis_results = []
    for result in sample.analysis_results:
        analysis_results.append(
            {
                "id": str(result.id),
                "type": result.analysis_type.value,
                "status": result.status.value,
                "started_at": (
                    result.started_at.isoformat() if result.started_at else None
                ),
                "completed_at": (
                    result.completed_at.isoformat() if result.completed_at else None
                ),
                "error_message": result.error_message,
            }
        )

    return {
        "sample_id": str(sample.id),
        "sha256": sample.sha256,
        "md5": sample.md5,
        "sha1": sample.sha1,
        "file_size": sample.file_size,
        "file_type": sample.file_type,
        "original_filename": sample.original_filename,
        "status": sample.status.value,
        "upload_timestamp": sample.upload_timestamp.isoformat(),
        "analysis_results": analysis_results,
    }


@router.get("/")
async def list_samples(
    limit: int = 100, offset: int = 0, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    List all uploaded samples with pagination.
    """
    if limit > 1000:
        limit = 1000

    samples = DatabaseOperations.get_all_samples(db, limit=limit, offset=offset)

    return {
        "total": len(samples),
        "limit": limit,
        "offset": offset,
        "samples": [
            {
                "sample_id": str(sample.id),
                "sha256": sample.sha256,
                "file_size": sample.file_size,
                "file_type": sample.file_type,
                "original_filename": sample.original_filename,
                "status": sample.status.value,
                "upload_timestamp": sample.upload_timestamp.isoformat(),
            }
            for sample in samples
        ],
    }
