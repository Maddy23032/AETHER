"""
Subfinder router - Fast subdomain discovery
Uses Python-based subdomain finder as fallback when subfinder CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonSubdomainFinder
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class SubfinderRequest(BaseModel):
    """Request model for subfinder"""
    target: str = Field(..., description="Target domain")
    silent: bool = Field(default=True, description="Show only subdomains in output")
    timeout: Optional[int] = Field(default=120, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "target": "example.com",
                "silent": True,
                "timeout": 120
            }
        }


@router.post("/subfinder", response_model=ReconResponse)
async def run_subfinder(request: SubfinderRequest):
    """
    Run subdomain discovery.
    Uses Python-based subdomain finder as fallback when subfinder CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Extract domain if URL provided
        if target.startswith(('http://', 'https://')):
            target = SecurityValidator.extract_host_from_url(target)
        
        # Check if subfinder CLI is available
        if ToolExecutor.is_tool_available(settings.SUBFINDER_PATH):
            # Use CLI subfinder
            args = ["-d", target, "-all"]
            if request.silent:
                args.append("-silent")
            
            command = ToolExecutor.build_command(settings.SUBFINDER_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_subdomain_enum(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based subdomain finder
            results = PythonSubdomainFinder.find_subdomains(target, request.timeout)
            stdout = PythonSubdomainFinder.format_output(results)
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'subdomains': results.get('subdomains', []),
                'count': results.get('count', 0)
            }
            using_fallback = True
        
        return ReconResponse(
            tool="subfinder" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "silent": request.silent,
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
