"""
Dirsearch router - Web path discovery
Uses Python-based directory buster as fallback when dirsearch CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonDirectoryBuster
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class DirsearchRequest(BaseModel):
    """Request model for dirsearch"""
    target: str = Field(..., description="Target URL")
    wordlist_size: str = Field(default="small", description="Wordlist size: small, medium")
    extensions: str = Field(default="php,html,js", description="File extensions to check")
    timeout: Optional[int] = Field(default=180, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "https://example.com",
                "wordlist_size": "small",
                "extensions": "php,html,js",
                "timeout": 180
            }
        }


@router.post("/dirsearch", response_model=ReconResponse)
async def run_dirsearch(request: DirsearchRequest):
    """
    Run web path and file discovery.
    Uses Python-based directory buster as fallback when dirsearch CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Check if dirsearch CLI is available
        if ToolExecutor.is_tool_available(settings.DIRSEARCH_PATH):
            # Use CLI dirsearch
            wordlist = settings.WORDLIST_SMALL if request.wordlist_size == "small" else settings.WORDLIST_MEDIUM
            args = [
                "-u", target,
                "-e", request.extensions,
                "-w", wordlist,
                "--plain-text-report=-"
            ]
            
            command = ToolExecutor.build_command(settings.DIRSEARCH_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_directory_scan(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based directory buster
            results = PythonDirectoryBuster.bust(target, request.timeout)
            stdout = PythonDirectoryBuster.format_output(results)
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'found_paths': [p['path'] for p in results.get('found_paths', [])],
                'status_codes': results.get('status_codes', {}),
                'details': results.get('found_paths', [])
            }
            using_fallback = True
        
        return ReconResponse(
            tool="dirsearch" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "wordlist_size": request.wordlist_size,
                "extensions": request.extensions,
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
