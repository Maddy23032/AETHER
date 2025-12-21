"""
TheHarvester router - OSINT data gathering
Uses Python-based email harvester as fallback when theHarvester CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonEmailHarvester
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class TheHarvesterRequest(BaseModel):
    """Request model for theHarvester"""
    target: str = Field(..., description="Target domain")
    sources: str = Field(default="google,bing,yahoo", description="Data sources (comma-separated)")
    limit: int = Field(default=100, ge=50, le=500, description="Results limit per source")
    timeout: Optional[int] = Field(default=180, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "example.com",
                "sources": "google,bing,yahoo",
                "limit": 100,
                "timeout": 180
            }
        }


@router.post("/theharvester", response_model=ReconResponse)
async def run_theharvester(request: TheHarvesterRequest):
    """
    Run OSINT data gathering.
    Uses Python-based harvester as fallback when theHarvester CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Extract domain if URL provided
        if target.startswith(('http://', 'https://')):
            target = SecurityValidator.extract_host_from_url(target)
        
        # Check if theHarvester CLI is available
        if ToolExecutor.is_tool_available(settings.THEHARVESTER_PATH):
            # Use CLI theHarvester
            args = [
                "-d", target,
                "-b", request.sources,
                "-l", str(request.limit)
            ]
            
            command = ToolExecutor.build_command(settings.THEHARVESTER_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_theharvester(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based email harvester
            results = PythonEmailHarvester.harvest(target, request.timeout)
            stdout = PythonEmailHarvester.format_output(results)
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'emails': results.get('emails', []),
                'hosts': results.get('hosts', []),
                'ips': results.get('ips', [])
            }
            using_fallback = True
        
        return ReconResponse(
            tool="theharvester" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "sources": request.sources,
                "limit": request.limit,
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
