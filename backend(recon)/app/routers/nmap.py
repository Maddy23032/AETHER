"""
Nmap router - Network discovery and port scanning
Uses Python-based scanner as fallback when nmap CLI is not available
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from app.core.security import SecurityValidator
from app.core.executor import ToolExecutor
from app.core.config import settings
from app.core.python_tools import PythonPortScanner
from app.models.responses import ReconResponse
from app.utils.parsers import OutputParser

router = APIRouter()


class NmapRequest(BaseModel):
    """Request model for nmap scan"""
    target: str = Field(..., description="Target domain or URL")
    scan_type: str = Field(default="service", description="Scan type: service, ping, syn, full")
    ports: str = Field(default="top-100", description="Port specification: top-100, 1-1000, 80,443")
    timeout: Optional[int] = Field(default=180, ge=30, le=300, description="Timeout in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target": "example.com",
                "scan_type": "service",
                "ports": "top-100",
                "timeout": 180
            }
        }


@router.post("/nmap", response_model=ReconResponse)
async def run_nmap(request: NmapRequest):
    """
    Run port scan on target.
    Uses nmap if available, otherwise falls back to Python-based scanner.
    """
    
    try:
        # Validate and sanitize target
        target = SecurityValidator.sanitize_target(request.target)
        
        # Validate ports
        if not SecurityValidator.validate_port_range(request.ports):
            raise ValueError("Invalid port specification")
        
        # Check if nmap CLI is available
        if ToolExecutor.is_tool_available(settings.NMAP_PATH):
            # Use CLI nmap
            args = []
            scan_types = {
                "service": ["-sV"],
                "ping": ["-sn"],
                "syn": ["-sS"],
                "full": ["-A"]
            }
            
            if request.scan_type not in scan_types:
                raise ValueError(f"Invalid scan type. Choose from: {', '.join(scan_types.keys())}")
            
            args.extend(scan_types[request.scan_type])
            
            if request.ports == "top-100":
                args.extend(["--top-ports", "100"])
            elif request.ports == "top-1000":
                args.extend(["--top-ports", "1000"])
            elif request.ports != "all":
                args.extend(["-p", request.ports])
            
            args.append(target)
            
            command = ToolExecutor.build_command(settings.NMAP_PATH, args)
            stdout, stderr, return_code, exec_time = ToolExecutor.execute(
                command,
                timeout=request.timeout
            )
            
            parsed = OutputParser.parse_nmap(stdout) if stdout else {}
            using_fallback = False
            
        else:
            # Use Python-based scanner
            results = PythonPortScanner.scan(target, request.ports, request.timeout)
            stdout = PythonPortScanner.format_output(results)
            stderr = None
            return_code = 0 if 'error' not in results else 1
            exec_time = float(results.get('scan_time', '0').replace('s', ''))
            
            parsed = {
                'hosts': [f"{results.get('host', target)} ({results.get('ip', 'N/A')})"],
                'open_ports': results.get('open_ports', []),
                'services': results.get('services', [])
            }
            using_fallback = True
        
        return ReconResponse(
            tool="nmap" + (" (Python fallback)" if using_fallback else ""),
            target=target,
            status="success" if return_code == 0 else "error",
            execution_time=f"{exec_time:.1f}s",
            parameters={
                "scan_type": request.scan_type,
                "ports": request.ports,
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
