"""
WhatWeb router - Web technology identification
Uses Python-based analyzer as fallback when whatweb CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonWebAnalyzer
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class WhatWebRequest(BaseModel):
    """Request model for whatweb scan"""
    target: str = Field(..., description="Target URL")
    aggression: int = Field(default=1, ge=1, le=3, description="Aggression level: 1 (stealthy) to 3 (aggressive)")
    timeout: Optional[int] = Field(default=120, ge=30, le=300, description="Timeout in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "target": "https://example.com",
                "aggression": 1,
                "timeout": 120
            }
        }


@router.post("/whatweb", response_model=ReconResponse)
async def run_whatweb(request: WhatWebRequest):
    """
    Run WhatWeb to identify web technologies.
    Uses Python-based analyzer as fallback when whatweb CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Check if whatweb CLI is available
        if ToolExecutor.is_tool_available(settings.WHATWEB_PATH):
            # Use CLI whatweb
            args = [
                "-a", str(request.aggression),
                "--color=never",
                target
            ]
            
            command = ToolExecutor.build_command(settings.WHATWEB_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_whatweb(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based analyzer
            results = PythonWebAnalyzer.analyze(target, request.timeout)
            stdout = PythonWebAnalyzer.format_output(results)
            stderr = None
            return_code = 0 if 'error' not in results else 1
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'technologies': results.get('technologies', []),
                'status_code': results.get('status_code'),
                'title': results.get('title'),
                'server': results.get('server')
            }
            using_fallback = True
        
        return ReconResponse(
            tool="whatweb" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "aggression": request.aggression,
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
