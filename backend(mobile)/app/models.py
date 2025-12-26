"""
Pydantic models for request/response schemas
"""
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


# === Request Models ===
class ScanRequest(BaseModel):
    file_hash: str


# === Response Models ===
class UploadResponse(BaseModel):
    success: bool
    file_hash: str
    filename: str
    message: str


class ScanResponse(BaseModel):
    success: bool
    file_hash: str
    scan_type: str
    status: str


class ReportResponse(BaseModel):
    success: bool
    file_hash: str
    report: Dict[str, Any]


class ScorecardResponse(BaseModel):
    success: bool
    file_hash: str
    scorecard: Dict[str, Any]


class ScrapedDataResponse(BaseModel):
    success: bool
    file_hash: str
    malware_lookup: Dict[str, str]
    apkid_analysis: List[Dict[str, str]]
    behaviour_analysis: List[Dict[str, str]]
    domain_malware_check: List[Dict[str, str]]
    urls: List[Dict[str, str]]
    emails: List[Dict[str, str]]


class FullAnalysisResponse(BaseModel):
    """Complete analysis combining all data sources"""
    success: bool
    file_hash: str
    filename: str
    scan_completed_at: datetime
    
    # From MobSF API
    json_report: Optional[Dict[str, Any]] = None
    scorecard: Optional[Dict[str, Any]] = None
    scan_logs: Optional[Dict[str, Any]] = None
    
    # From HTML Scraping
    scraped_data: Optional[Dict[str, Any]] = None
    
    # PDF
    pdf_available: bool = False
    pdf_path: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    mobsf_connected: bool
    api_key_available: bool
    version: str = "1.0.0"


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    detail: Optional[str] = None
