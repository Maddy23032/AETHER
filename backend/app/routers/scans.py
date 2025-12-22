"""Scan management REST API endpoints."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
import structlog

from app.models.scan import (
    ScanConfig,
    ScanJob,
    ScanResult,
    ScanStatus,
    Vulnerability,
    SeverityLevel,
)
from app.services.scanner import ScannerOrchestrator

router = APIRouter()
logger = structlog.get_logger()

# In-memory store for demo (replace with database in production)
scan_jobs: dict[str, ScanJob] = {}
scan_results: dict[str, ScanResult] = {}


class CreateScanRequest(BaseModel):
    """Request body for creating a new scan."""

    target_url: HttpUrl = Field(..., description="Target URL to scan")
    config: Optional[ScanConfig] = Field(default=None, description="Scan configuration options")


class CreateScanResponse(BaseModel):
    """Response after creating a scan job."""

    scan_id: str
    status: ScanStatus
    message: str


class ScanListResponse(BaseModel):
    """Response containing list of scans."""

    scans: List[ScanJob]
    total: int


@router.post("/", response_model=CreateScanResponse)
async def create_scan(request: CreateScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new vulnerability scan job.
    
    The scan runs asynchronously in the background. Use the returned scan_id
    to check status via GET /api/scans/{scan_id} or subscribe to real-time
    updates via WebSocket at /ws/scans/{scan_id}.
    """
    scan_id = str(uuid4())
    config = request.config or ScanConfig()
    
    scan_job = ScanJob(
        id=scan_id,
        target_url=str(request.target_url),
        status=ScanStatus.PENDING,
        config=config,
        created_at=datetime.utcnow(),
    )
    
    scan_jobs[scan_id] = scan_job
    
    logger.info("Scan job created", scan_id=scan_id, target=str(request.target_url))
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, scan_id, str(request.target_url), config)
    
    return CreateScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message="Scan job created successfully. Subscribe to WebSocket for real-time updates.",
    )


async def run_scan_task(scan_id: str, target_url: str, config: ScanConfig):
    """Background task to execute the scan."""
    try:
        scan_jobs[scan_id].status = ScanStatus.RUNNING
        scan_jobs[scan_id].started_at = datetime.utcnow()
        
        logger.info("Starting scan", scan_id=scan_id, target=target_url)
        
        orchestrator = ScannerOrchestrator(scan_id, target_url, config)
        result = await orchestrator.run()
        
        scan_results[scan_id] = result
        scan_jobs[scan_id].status = ScanStatus.COMPLETED
        scan_jobs[scan_id].completed_at = datetime.utcnow()
        scan_jobs[scan_id].vulnerabilities_found = len(result.vulnerabilities)
        
        logger.info(
            "Scan completed",
            scan_id=scan_id,
            vulnerabilities=len(result.vulnerabilities),
        )
        
    except Exception as e:
        logger.error("Scan failed", scan_id=scan_id, error=str(e))
        scan_jobs[scan_id].status = ScanStatus.FAILED
        scan_jobs[scan_id].error_message = str(e)


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
):
    """List all scan jobs with pagination."""
    all_scans = list(scan_jobs.values())
    all_scans.sort(key=lambda x: x.created_at, reverse=True)
    
    paginated = all_scans[offset : offset + limit]
    
    return ScanListResponse(scans=paginated, total=len(all_scans))


@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan(scan_id: str):
    """Get details of a specific scan job."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_jobs[scan_id]


@router.get("/{scan_id}/results", response_model=ScanResult)
async def get_scan_results(scan_id: str):
    """Get the results of a completed scan."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    job = scan_jobs[scan_id]
    
    if job.status == ScanStatus.PENDING:
        raise HTTPException(status_code=400, detail="Scan has not started yet")
    
    if job.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Scan is still in progress")
    
    if job.status == ScanStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {job.error_message}",
        )
    
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return scan_results[scan_id]


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan job."""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    job = scan_jobs[scan_id]
    
    if job.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan in {job.status} status",
        )
    
    job.status = ScanStatus.CANCELLED
    logger.info("Scan cancelled", scan_id=scan_id)
    
    return {"message": "Scan cancelled successfully"}


@router.get("/{scan_id}/export")
async def export_scan_results(scan_id: str, format: str = Query(default="json")):
    """
    Export scan results in various formats.
    
    Supported formats: json, rag (optimized for RAG ingestion)
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    result = scan_results[scan_id]
    
    if format == "json":
        return result
    
    elif format == "rag":
        # RAG-optimized format for embedding
        return result.to_rag_format()
    
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'json' or 'rag'.",
        )
