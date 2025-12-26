"""
DNSenum router - DNS enumeration
Uses Python-based DNS enumerator as fallback when dnsenum CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonDNSEnumerator
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class DnsenumRequest(BaseModel):
    """Request model for dnsenum"""
    target: str = Field(..., description="Target domain")
    timeout: Optional[int] = Field(default=120, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "target": "example.com",
                "timeout": 120
            }
        }


@router.post("/dnsenum", response_model=ReconResponse)
async def run_dnsenum(request: DnsenumRequest):
    """
    Run DNS enumeration.
    Uses Python-based DNS enumerator as fallback when dnsenum CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Extract domain if URL provided
        if target.startswith(('http://', 'https://')):
            target = SecurityValidator.extract_host_from_url(target)
        
        # Check if dnsenum CLI is available
        if ToolExecutor.is_tool_available(settings.DNSENUM_PATH):
            # Use CLI dnsenum
            args = [
                target,
                "--noreverse",
                "--nocolor"
            ]
            
            command = ToolExecutor.build_command(settings.DNSENUM_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_dnsenum(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based DNS enumerator
            results = PythonDNSEnumerator.enumerate(target, request.timeout)
            stdout = PythonDNSEnumerator.format_output(results)
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'nameservers': results.get('nameservers', []),
                'mx_records': results.get('mx_records', []),
                'hosts': results.get('ip_addresses', []),
                'records': results.get('records', {})
            }
            using_fallback = True
        
        return ReconResponse(
            tool="dnsenum" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={"fallback_mode": using_fallback},
            results={
                "raw": stdout,
                "parsed": parsed
            },
            errors=stderr if stderr and return_code != 0 else None
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
