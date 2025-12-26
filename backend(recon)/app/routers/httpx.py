"""
HTTPX router - Fast HTTP toolkit
Uses Python-based HTTP prober as fallback when httpx CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonHTTPProbe
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class HttpxRequest(BaseModel):
    """Request model for httpx"""
    target: str = Field(..., description="Target URL or domain")
    tech_detect: bool = Field(default=True, description="Detect web technologies")
    status_code: bool = Field(default=True, description="Display status code")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    timeout: Optional[int] = Field(default=120, ge=30, le=300, description="Timeout in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "target": "example.com",
                "tech_detect": True,
                "status_code": True,
                "follow_redirects": True,
                "timeout": 120
            }
        }


@router.post("/httpx", response_model=ReconResponse)
async def run_httpx(request: HttpxRequest):
    """
    Run HTTP probing and analysis.
    Uses Python-based HTTP prober as fallback when httpx CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Check if httpx CLI is available
        if ToolExecutor.is_tool_available(settings.HTTPX_PATH):
            # Use CLI httpx
            args = ["-u", target, "-silent", "-no-color"]
            
            if request.tech_detect:
                args.append("-tech-detect")
            if request.status_code:
                args.append("-status-code")
            if request.follow_redirects:
                args.append("-follow-redirects")
            
            args.append("-json")
            
            command = ToolExecutor.build_command(settings.HTTPX_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_httpx(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based HTTP prober
            results = PythonHTTPProbe.probe(target, request.timeout)
            stdout = PythonHTTPProbe.format_output(results)
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'live_hosts': results.get('live_hosts', []),
                'probes': results.get('probes', []),
                'status_codes': {}
            }
            using_fallback = True
        
        return ReconResponse(
            tool="httpx" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "tech_detect": request.tech_detect,
                "status_code": request.status_code,
                "follow_redirects": request.follow_redirects,
                "fallback_mode": using_fallback
            },
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
