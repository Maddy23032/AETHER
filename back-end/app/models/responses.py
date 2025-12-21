"""
Response models for API endpoints
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel


class ReconResponse(BaseModel):
    """Standard response format for all reconnaissance tools"""
    tool: str
    target: str
    status: str  # "success" or "error"
    execution_time: str
    parameters: Dict[str, Any]
    results: Dict[str, Any]  # Contains "raw" and "parsed" keys
    errors: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "tool": "nmap",
                "target": "example.com",
                "status": "success",
                "execution_time": "12.3s",
                "parameters": {
                    "ports": "top-100",
                    "scan_type": "service"
                },
                "results": {
                    "raw": "Nmap scan report...",
                    "parsed": {}
                },
                "errors": None
            }
        }
