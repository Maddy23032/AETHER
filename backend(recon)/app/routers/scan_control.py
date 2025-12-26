"""
Scan control router - Cancel and manage running scans
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List

from app.core.scan_manager import scan_manager, ScanStatus


router = APIRouter()


class CancelRequest(BaseModel):
    """Request model for cancelling scans"""
    scan_id: Optional[str] = Field(None, description="Specific scan ID to cancel")
    target: Optional[str] = Field(None, description="Cancel all scans for this target")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "abc-123",
                "target": "example.com"
            }
        }


class CancelResponse(BaseModel):
    """Response model for cancel operation"""
    success: bool
    message: str
    cancelled_count: int = 0


class ScanStatusResponse(BaseModel):
    """Response model for scan status"""
    scan_id: str
    tool: str
    target: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None


class ActiveScansResponse(BaseModel):
    """Response model for listing active scans"""
    active_scans: List[ScanStatusResponse]
    total_count: int


@router.post("/cancel", response_model=CancelResponse)
async def cancel_scan(request: CancelRequest):
    """
    Cancel a running scan by scan_id or cancel all scans for a target.
    At least one of scan_id or target must be provided.
    """
    if not request.scan_id and not request.target:
        raise HTTPException(
            status_code=400, 
            detail="Either scan_id or target must be provided"
        )
    
    if request.scan_id:
        # Cancel specific scan
        success, message = scan_manager.cancel_scan(request.scan_id)
        return CancelResponse(
            success=success,
            message=message,
            cancelled_count=1 if success else 0
        )
    
    if request.target:
        # Cancel all scans for target
        cancelled, failed = scan_manager.cancel_all_for_target(request.target)
        
        if cancelled == 0 and failed == 0:
            return CancelResponse(
                success=True,
                message=f"No active scans found for target: {request.target}",
                cancelled_count=0
            )
        
        return CancelResponse(
            success=failed == 0,
            message=f"Cancelled {cancelled} scan(s)" + (f", {failed} failed" if failed > 0 else ""),
            cancelled_count=cancelled
        )
    
    return CancelResponse(success=False, message="No action taken", cancelled_count=0)


@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get the status of a specific scan.
    """
    scan = scan_manager.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return ScanStatusResponse(
        scan_id=scan.scan_id,
        tool=scan.tool,
        target=scan.target,
        status=scan.status.value,
        started_at=scan.started_at.isoformat(),
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        error=scan.error
    )


@router.get("/active", response_model=ActiveScansResponse)
async def get_active_scans():
    """
    Get all currently active (running or pending) scans.
    """
    active = scan_manager.get_active_scans()
    
    return ActiveScansResponse(
        active_scans=[
            ScanStatusResponse(
                scan_id=scan.scan_id,
                tool=scan.tool,
                target=scan.target,
                status=scan.status.value,
                started_at=scan.started_at.isoformat(),
                completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
                error=scan.error
            )
            for scan in active
        ],
        total_count=len(active)
    )


@router.post("/cancel-all", response_model=CancelResponse)
async def cancel_all_scans():
    """
    Cancel ALL running scans across all targets.
    Use with caution.
    """
    active = scan_manager.get_active_scans()
    cancelled = 0
    failed = 0
    
    for scan in active:
        success, _ = scan_manager.cancel_scan(scan.scan_id)
        if success:
            cancelled += 1
        else:
            failed += 1
    
    return CancelResponse(
        success=failed == 0,
        message=f"Cancelled {cancelled} scan(s)" + (f", {failed} failed" if failed > 0 else ""),
        cancelled_count=cancelled
    )
