"""
Scan Manager - Manages running scans and provides cancellation functionality
"""

import asyncio
import subprocess
import time
from typing import Dict, Optional, Any, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class ScanJob:
    """Represents a running or completed scan job"""
    scan_id: str
    tool: str
    target: str
    status: ScanStatus
    process: Optional[subprocess.Popen] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tool": self.tool,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error
        }


class ScanManager:
    """
    Manages running scans, allowing tracking and cancellation.
    Singleton pattern to ensure one manager across the application.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._scans: Dict[str, ScanJob] = {}
        self._active_processes: Dict[str, subprocess.Popen] = {}
        self._cancel_flags: Dict[str, bool] = {}
        self._initialized = True
    
    def register_scan(self, scan_id: str, tool: str, target: str) -> ScanJob:
        """Register a new scan job"""
        job = ScanJob(
            scan_id=scan_id,
            tool=tool,
            target=target,
            status=ScanStatus.PENDING
        )
        self._scans[scan_id] = job
        self._cancel_flags[scan_id] = False
        return job
    
    def set_process(self, scan_id: str, process: subprocess.Popen):
        """Associate a subprocess with a scan"""
        if scan_id in self._scans:
            self._scans[scan_id].process = process
            self._scans[scan_id].status = ScanStatus.RUNNING
            self._active_processes[scan_id] = process
    
    def is_cancelled(self, scan_id: str) -> bool:
        """Check if a scan has been cancelled"""
        return self._cancel_flags.get(scan_id, False)
    
    def complete_scan(
        self, 
        scan_id: str, 
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Mark a scan as completed"""
        if scan_id in self._scans:
            job = self._scans[scan_id]
            if self._cancel_flags.get(scan_id, False):
                job.status = ScanStatus.CANCELLED
            elif error:
                job.status = ScanStatus.ERROR
                job.error = error
            else:
                job.status = ScanStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.result = result
            
            # Clean up process references
            if scan_id in self._active_processes:
                del self._active_processes[scan_id]
    
    def cancel_scan(self, scan_id: str) -> Tuple[bool, str]:
        """
        Cancel a running scan by its ID.
        Returns (success, message)
        """
        # Set the cancel flag first
        self._cancel_flags[scan_id] = True
        
        if scan_id not in self._scans:
            return False, f"Scan {scan_id} not found"
        
        job = self._scans[scan_id]
        
        if job.status == ScanStatus.COMPLETED:
            return False, "Scan already completed"
        
        if job.status == ScanStatus.CANCELLED:
            return True, "Scan already cancelled"
        
        # Try to terminate the process
        if scan_id in self._active_processes:
            process = self._active_processes[scan_id]
            try:
                process.terminate()
                # Give it a moment to terminate gracefully
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Force kill if needed
                    process.kill()
                    process.wait()
            except Exception as e:
                return False, f"Error terminating process: {str(e)}"
        
        job.status = ScanStatus.CANCELLED
        job.completed_at = datetime.utcnow()
        
        return True, f"Scan {scan_id} cancelled successfully"
    
    def cancel_all_for_target(self, target: str) -> Tuple[int, int]:
        """
        Cancel all running scans for a target.
        Returns (cancelled_count, failed_count)
        """
        cancelled = 0
        failed = 0
        
        for scan_id, job in self._scans.items():
            if job.target == target and job.status == ScanStatus.RUNNING:
                success, _ = self.cancel_scan(scan_id)
                if success:
                    cancelled += 1
                else:
                    failed += 1
        
        return cancelled, failed
    
    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID"""
        return self._scans.get(scan_id)
    
    def get_active_scans(self) -> List[ScanJob]:
        """Get all running scans"""
        return [
            job for job in self._scans.values()
            if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
        ]
    
    def get_scans_for_target(self, target: str) -> List[ScanJob]:
        """Get all scans for a specific target"""
        return [
            job for job in self._scans.values()
            if job.target == target
        ]
    
    def cleanup_old_scans(self, max_age_seconds: int = 3600):
        """Remove completed scans older than max_age_seconds"""
        now = datetime.utcnow()
        to_remove = []
        
        for scan_id, job in self._scans.items():
            if job.completed_at:
                age = (now - job.completed_at).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(scan_id)
        
        for scan_id in to_remove:
            del self._scans[scan_id]
            if scan_id in self._cancel_flags:
                del self._cancel_flags[scan_id]


# Global scan manager instance
scan_manager = ScanManager()
