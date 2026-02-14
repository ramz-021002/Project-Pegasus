"""
Analysis results router for retrieving completed analysis data.
"""
import logging
from typing import Dict, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query
from datetime import datetime
from sqlalchemy.orm import Session

from app.database import (
    get_db, DatabaseOperations, Sample, AnalysisType, AnalysisStatus, SampleStatus
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{sample_id}")
async def get_analysis_results(
    sample_id: str,
    db: Session = Depends(get_db)
) -> Dict:
    """
    Get complete analysis results for a sample.

    Args:
        sample_id: UUID of the sample
        db: Database session

    Returns:
        Complete analysis results with all data
    """
    # Validate and get sample
    try:
        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )

    # Build response with all analysis data
    response = {
        "sample_id": str(sample.id),
        "sha256": sample.sha256,
        "md5": sample.md5,
        "sha1": sample.sha1,
        "file_size": sample.file_size,
        "file_type": sample.file_type,
        "original_filename": sample.original_filename,
        "status": sample.status.value,
        "upload_timestamp": sample.upload_timestamp.isoformat(),
        "analysis_results": {}
    }

    # Add each analysis type results. For types with multiple entries (e.g. repeated dynamic runs)
    # prefer the most recent completed run with a non-null results_json, otherwise fall back to
    # the latest run by start time.
    results_by_type = {}
    for result in sample.analysis_results:
        results_by_type.setdefault(result.analysis_type.value, []).append(result)

    for analysis_key, results_list in results_by_type.items():
        # Prefer completed runs with results
        chosen = None
        # sort by started_at desc (None -> epoch)
        def started_key(r):
            return r.started_at or datetime.fromtimestamp(0)

        sorted_runs = sorted(results_list, key=started_key, reverse=True)
        for r in sorted_runs:
            if r.results_json:
                chosen = r
                break
        if not chosen:
            chosen = sorted_runs[0]

        response["analysis_results"][analysis_key] = {
            "id": str(chosen.id),
            "status": chosen.status.value,
            "started_at": chosen.started_at.isoformat() if chosen.started_at else None,
            "completed_at": chosen.completed_at.isoformat() if chosen.completed_at else None,
            "results": chosen.results_json,
            "error_message": chosen.error_message
        }

    # Add network indicators
    indicators = DatabaseOperations.get_indicators_for_sample(db, sample_uuid)
    response["network_indicators"] = [
        {
            "type": indicator.indicator_type.value,
            "value": indicator.value,
            "confidence": indicator.confidence,
            "context": indicator.context,
            "first_seen": indicator.first_seen.isoformat()
        }
        for indicator in indicators
    ]

    # Fetch additional data for analysis results
    results = {}
    for analysis_result in sample.analysis_results:
        if analysis_result.results_json:
            results.update({
                "network_logs": analysis_result.results_json.get("network_logs"),
                "commands_executed": analysis_result.results_json.get("commands_executed"),
                "files_accessed": analysis_result.results_json.get("files_accessed"),
                "qemu_output": analysis_result.results_json.get("qemu_output"),
            })

    return response


@router.get("/{sample_id}/static")
async def get_static_analysis(
    sample_id: str,
    db: Session = Depends(get_db)
) -> Dict:
    """
    Get static analysis results only.

    Args:
        sample_id: UUID of the sample
        db: Database session

    Returns:
        Static analysis results
    """
    try:
        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )

    # Find static analysis result
    for result in sample.analysis_results:
        if result.analysis_type == AnalysisType.STATIC:
            return {
                "sample_id": str(sample.id),
                "analysis_type": "static",
                "status": result.status.value,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "results": result.results_json,
                "error_message": result.error_message
            }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Static analysis not found for this sample"
    )


@router.get("/{sample_id}/dynamic")
async def get_dynamic_analysis(
    sample_id: str,
    db: Session = Depends(get_db)
) -> Dict:
    """
    Get dynamic analysis results only.

    Args:
        sample_id: UUID of the sample
        db: Database session

    Returns:
        Dynamic analysis results
    """
    try:
        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )

    # Find dynamic analysis result(s) and pick the most relevant one
    dyn_results = [r for r in sample.analysis_results if r.analysis_type == AnalysisType.DYNAMIC]
    if not dyn_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dynamic analysis not found for this sample"
        )

    # Sort by started_at desc
    dyn_results_sorted = sorted(dyn_results, key=lambda r: r.started_at or datetime.fromtimestamp(0), reverse=True)
    chosen = None
    for r in dyn_results_sorted:
        if r.results_json:
            chosen = r
            break
    if not chosen:
        chosen = dyn_results_sorted[0]

    return {
        "sample_id": str(sample.id),
        "analysis_type": "dynamic",
        "status": chosen.status.value,
        "started_at": chosen.started_at.isoformat() if chosen.started_at else None,
        "completed_at": chosen.completed_at.isoformat() if chosen.completed_at else None,
        "results": chosen.results_json,
        "error_message": chosen.error_message
    }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Dynamic analysis not found for this sample"
    )


@router.get("/{sample_id}/indicators")
async def get_network_indicators(
    sample_id: str,
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type"),
    db: Session = Depends(get_db)
) -> Dict:
    """
    Get network indicators extracted from analysis.

    Args:
        sample_id: UUID of the sample
        indicator_type: Optional filter by type (ip, domain, url, email)
        db: Database session

    Returns:
        List of network indicators
    """
    try:
        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )

    indicators = DatabaseOperations.get_indicators_for_sample(db, sample_uuid)

    # Filter by type if specified
    if indicator_type:
        indicators = [i for i in indicators if i.indicator_type.value == indicator_type.lower()]

    return {
        "sample_id": str(sample.id),
        "total_indicators": len(indicators),
        "indicators": [
            {
                "id": str(indicator.id),
                "type": indicator.indicator_type.value,
                "value": indicator.value,
                "confidence": indicator.confidence,
                "context": indicator.context,
                "first_seen": indicator.first_seen.isoformat()
            }
            for indicator in indicators
        ]
    }


@router.post("/{sample_id}/reanalyze")
async def reanalyze_sample(
    sample_id: str,
    db: Session = Depends(get_db)
) -> Dict:
    """
    Trigger re-analysis of an existing sample and overwrite previous results.

    Args:
        sample_id: UUID of the sample
        db: Database session

    Returns:
        Status message indicating re-analysis was started
    """
    try:
        sample_uuid = uuid.UUID(sample_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format"
        )

    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )

    # Mark existing analysis results as ready-to-run and clear results_json
    for result in sample.analysis_results:
        result.status = AnalysisStatus.RUNNING
        result.results_json = None
        result.error_message = None
    sample.status = SampleStatus.ANALYZING
    db.commit()

    # Trigger Celery task for analysis
    from app.tasks.orchestration import analyze_sample
    analyze_sample.delay(str(sample.id))

    return {
        "message": "Re-analysis started",
        "sample_id": str(sample.id),
        "status": sample.status.value
    }
    


@router.get("/")
async def search_samples(
    sha256: Optional[str] = Query(None, description="Search by SHA256 hash"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
) -> Dict:
    """
    Search and filter analysis results.

    Args:
        sha256: Optional SHA256 hash to search for
        status_filter: Optional status filter
        limit: Maximum results to return
        offset: Number of results to skip
        db: Database session

    Returns:
        List of matching samples with summary
    """
    # If SHA256 provided, search for specific sample
    if sha256:
        sample = DatabaseOperations.get_sample_by_sha256(db, sha256)
        if not sample:
            return {"total": 0, "samples": []}

        return {
            "total": 1,
            "samples": [{
                "sample_id": str(sample.id),
                "sha256": sample.sha256,
                "md5": sample.md5,
                "file_size": sample.file_size,
                "file_type": sample.file_type,
                "original_filename": sample.original_filename,
                "status": sample.status.value,
                "upload_timestamp": sample.upload_timestamp.isoformat(),
                "analysis_count": len(sample.analysis_results)
            }]
        }

    # Get all samples with optional status filter
    samples = DatabaseOperations.get_all_samples(db, limit=limit, offset=offset)

    if status_filter:
        samples = [s for s in samples if s.status.value == status_filter]

    return {
        "total": len(samples),
        "limit": limit,
        "offset": offset,
        "samples": [
            {
                "sample_id": str(sample.id),
                "sha256": sample.sha256,
                "md5": sample.md5,
                "file_size": sample.file_size,
                "file_type": sample.file_type,
                "original_filename": sample.original_filename,
                "status": sample.status.value,
                "upload_timestamp": sample.upload_timestamp.isoformat(),
                "analysis_count": len(sample.analysis_results)
            }
            for sample in samples
        ]
    }
