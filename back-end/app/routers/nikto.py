"""
Nikto router - Web server vulnerability scanner
Uses Python-based vulnerability scanner as fallback when nikto CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonVulnScanner
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class NiktoRequest(BaseModel):
    """Request model for nikto scan"""
    target: str = Field(..., description="Target URL")
    ssl: bool = Field(default=False, description="Force SSL mode")
    timeout: Optional[int] = Field(default=240, ge=60, le=300, description="Timeout in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "https://example.com",
                "ssl": True,
                "timeout": 240
            }
        }


@router.post("/nikto", response_model=ReconResponse)
async def run_nikto(request: NiktoRequest):
    """
    Run web server vulnerability scan.
    Uses Python-based scanner as fallback when nikto CLI is not available.
    
    Performs comprehensive security checks including:
    - Missing security headers
    - Outdated server software detection
    - Sensitive file exposure
    - Common misconfigurations
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}" if request.ssl else f"http://{target}"
        
        # Check if nikto CLI is available
        if ToolExecutor.is_tool_available(settings.NIKTO_PATH):
            # Use CLI nikto
            args = [
                "-h", target,
                "-nointeractive",
                "-Format", "txt"
            ]
            
            if request.ssl:
                args.append("-ssl")
            
            command = ToolExecutor.build_command(settings.NIKTO_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_nikto(stdout) if stdout else {}
            using_fallback = False
        else:
            # Use Python-based vulnerability scanner
            results = PythonVulnScanner.scan(target, request.ssl, request.timeout)
            stdout = PythonVulnScanner.format_output(results)
            
            parsed = {
                'vulnerabilities': results.get('vulnerabilities', []),
                'missing_headers': results.get('missing_headers', []),
                'sensitive_files': results.get('sensitive_files', []),
                'server_info': results.get('server_info', {}),
                'ssl_info': results.get('ssl_info', {}),
                'vulnerability_count': len(results.get('vulnerabilities', []))
            }
            
            stderr = None
            return_code = 0 if 'error' not in results else 1
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            using_fallback = True
        
        return ReconResponse(
            tool="nikto" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "ssl": request.ssl,
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
