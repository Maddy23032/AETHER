"""
Gobuster router - Directory/DNS brute-forcing
Uses Python-based tools as fallback when gobuster CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonDirectoryBuster, PythonSubdomainFinder
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class GobusterRequest(BaseModel):
    """Request model for gobuster"""
    target: str = Field(..., description="Target URL")
    mode: str = Field(default="dir", description="Mode: dir (directory), dns (subdomain)")
    wordlist_size: str = Field(default="small", description="Wordlist size: small, medium")
    timeout: Optional[int] = Field(default=180, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "https://example.com",
                "mode": "dir",
                "wordlist_size": "small",
                "timeout": 180
            }
        }


@router.post("/gobuster", response_model=ReconResponse)
async def run_gobuster(request: GobusterRequest):
    """
    Run directory or DNS enumeration.
    Uses Python-based tools as fallback when gobuster CLI is not available.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Validate mode
        if request.mode not in ["dir", "dns"]:
            raise ValueError("Mode must be 'dir' or 'dns'")
        
        # Check if gobuster CLI is available
        if ToolExecutor.is_tool_available(settings.GOBUSTER_PATH):
            # Use CLI gobuster
            wordlist = settings.WORDLIST_SMALL if request.wordlist_size == "small" else settings.WORDLIST_MEDIUM
            args = [request.mode]
            
            if request.mode == "dir":
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                args.extend(["-u", target])
            else:
                if target.startswith(('http://', 'https://')):
                    target = SecurityValidator.extract_host_from_url(target)
                args.extend(["-d", target])
            
            args.extend(["-w", wordlist, "-q"])
            
            command = ToolExecutor.build_command(settings.GOBUSTER_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            if request.mode == "dns":
                parsed = OutputParser.parse_subdomain_enum(stdout) if stdout else {}
            else:
                parsed = OutputParser.parse_directory_scan(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based tools
            if request.mode == "dir":
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                results = PythonDirectoryBuster.bust(target, request.timeout)
                stdout = PythonDirectoryBuster.format_output(results)
                parsed = {
                    'found_paths': [p['path'] for p in results.get('found_paths', [])],
                    'status_codes': results.get('status_codes', {})
                }
            else:
                if target.startswith(('http://', 'https://')):
                    target = SecurityValidator.extract_host_from_url(target)
                results = PythonSubdomainFinder.find_subdomains(target, request.timeout)
                stdout = PythonSubdomainFinder.format_output(results)
                parsed = {
                    'subdomains': results.get('subdomains', []),
                    'count': results.get('count', 0)
                }
            
            stderr = None
            return_code = 0
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            using_fallback = True
        
        return ReconResponse(
            tool="gobuster" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "mode": request.mode,
                "wordlist_size": request.wordlist_size,
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
