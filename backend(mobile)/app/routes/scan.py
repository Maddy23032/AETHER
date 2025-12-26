"""
Scan Routes - API endpoints for mobile security scanning
"""
import os
import hashlib
import aiofiles
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from typing import Optional

from app.config import get_settings
from app.models import (
    UploadResponse, ScanResponse, ReportResponse, 
    ScorecardResponse, ScrapedDataResponse, FullAnalysisResponse,
    ErrorResponse
)
from app.services.mobsf_service import get_mobsf_service
from app.services.scraper_service import get_scraper_service

router = APIRouter(prefix="/scan", tags=["Scanning"])
settings = get_settings()


def compute_file_hash(file_path: str) -> str:
    """Compute MD5 hash of file."""
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """
    Upload APK/IPA file to MobSF.
    The file is saved locally first, then uploaded to MobSF.
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    ext = file.filename.lower().split(".")[-1]
    if ext not in ["apk", "ipa", "appx", "zip"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Supported: APK, IPA, APPX, ZIP")
    
    try:
        # Save file locally
        os.makedirs(settings.upload_dir, exist_ok=True)
        file_path = os.path.join(settings.upload_dir, file.filename)
        
        async with aiofiles.open(file_path, "wb") as f:
            content = await file.read()
            await f.write(content)
        
        # Upload to MobSF
        mobsf = get_mobsf_service()
        result = await mobsf.upload_file(file_path, file.filename)
        
        file_hash = result.get("hash") or result.get("hashes")
        
        return UploadResponse(
            success=True,
            file_hash=file_hash,
            filename=file.filename,
            message="File uploaded successfully"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/{file_hash}", response_model=ScanResponse)
async def run_scan(file_hash: str):
    """
    Run static analysis scan on uploaded file.
    """
    try:
        mobsf = get_mobsf_service()
        result = await mobsf.run_scan(file_hash)
        
        return ScanResponse(
            success=True,
            file_hash=file_hash,
            scan_type=result.get("scan_type", "static"),
            status="completed"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{file_hash}", response_model=ReportResponse)
async def get_report(file_hash: str):
    """
    Get JSON report for scanned file.
    """
    try:
        mobsf = get_mobsf_service()
        report = await mobsf.get_json_report(file_hash)
        
        return ReportResponse(
            success=True,
            file_hash=file_hash,
            report=report
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scorecard/{file_hash}", response_model=ScorecardResponse)
async def get_scorecard(file_hash: str):
    """
    Get security scorecard for scanned file.
    """
    try:
        mobsf = get_mobsf_service()
        scorecard = await mobsf.get_scorecard(file_hash)
        
        return ScorecardResponse(
            success=True,
            file_hash=file_hash,
            scorecard=scorecard
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scraped/{file_hash}", response_model=ScrapedDataResponse)
async def get_scraped_data(file_hash: str):
    """
    Get scraped data from static analyzer HTML page.
    Includes: malware lookups, APKiD, behaviour analysis, URLs, emails.
    """
    try:
        scraper = get_scraper_service()
        data = await scraper.scrape_static_analyzer(file_hash)
        
        if "error" in data:
            raise HTTPException(status_code=500, detail=data["error"])
        
        return ScrapedDataResponse(
            success=True,
            file_hash=file_hash,
            malware_lookup=data.get("malware_lookup", {}),
            apkid_analysis=data.get("apkid_analysis", []),
            behaviour_analysis=data.get("behaviour_analysis", []),
            domain_malware_check=data.get("domain_malware_check", []),
            urls=data.get("urls", []),
            emails=data.get("emails", [])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full-analysis", response_model=FullAnalysisResponse)
async def run_full_analysis(file: UploadFile = File(...)):
    """
    Complete analysis pipeline:
    1. Upload file to MobSF
    2. Run static scan
    3. Fetch JSON report
    4. Fetch scorecard
    5. Fetch scan logs
    6. Scrape HTML for additional data
    7. Download PDF report
    """
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    ext = file.filename.lower().split(".")[-1]
    if ext not in ["apk", "ipa", "appx", "zip"]:
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    try:
        mobsf = get_mobsf_service()
        scraper = get_scraper_service()
        
        # 1. Save and upload file
        os.makedirs(settings.upload_dir, exist_ok=True)
        file_path = os.path.join(settings.upload_dir, file.filename)
        
        async with aiofiles.open(file_path, "wb") as f:
            content = await file.read()
            await f.write(content)
        
        upload_result = await mobsf.upload_file(file_path, file.filename)
        file_hash = upload_result.get("hash") or upload_result.get("hashes")
        
        # 2. Run scan
        await mobsf.run_scan(file_hash)
        
        # 3-5. Fetch reports (parallel)
        import asyncio
        json_report, scorecard, scan_logs = await asyncio.gather(
            mobsf.get_json_report(file_hash),
            mobsf.get_scorecard(file_hash),
            mobsf.get_scan_logs(file_hash),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(json_report, Exception):
            json_report = {"error": str(json_report)}
        if isinstance(scorecard, Exception):
            scorecard = {"error": str(scorecard)}
        if isinstance(scan_logs, Exception):
            scan_logs = {"error": str(scan_logs)}
        
        # 6. Scrape HTML data
        scraped_data = await scraper.scrape_static_analyzer(file_hash)
        
        # 7. Download PDF
        os.makedirs(settings.reports_dir, exist_ok=True)
        pdf_path = os.path.join(settings.reports_dir, f"{file_hash}_report.pdf")
        pdf_available = await mobsf.download_pdf(file_hash, pdf_path)
        
        return FullAnalysisResponse(
            success=True,
            file_hash=file_hash,
            filename=file.filename,
            scan_completed_at=datetime.utcnow(),
            json_report=json_report if "error" not in json_report else None,
            scorecard=scorecard if "error" not in scorecard else None,
            scan_logs=scan_logs if "error" not in scan_logs else None,
            scraped_data=scraped_data if "error" not in scraped_data else None,
            pdf_available=pdf_available,
            pdf_path=pdf_path if pdf_available else None
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_scan_history(page: int = 1, page_size: int = 10):
    """
    Get list of recent scans from MobSF.
    """
    try:
        mobsf = get_mobsf_service()
        return await mobsf.get_recent_scans(page, page_size)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{file_hash}")
async def delete_scan(file_hash: str):
    """
    Delete a scan from MobSF.
    """
    try:
        mobsf = get_mobsf_service()
        return await mobsf.delete_scan(file_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pdf/{file_hash}")
async def download_pdf(file_hash: str):
    """
    Download PDF report for scanned file.
    """
    from fastapi.responses import FileResponse
    
    pdf_path = os.path.join(settings.reports_dir, f"{file_hash}_report.pdf")
    
    if os.path.exists(pdf_path):
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"{file_hash}_report.pdf"
        )
    
    # Try to download from MobSF
    try:
        mobsf = get_mobsf_service()
        os.makedirs(settings.reports_dir, exist_ok=True)
        
        if await mobsf.download_pdf(file_hash, pdf_path):
            return FileResponse(
                pdf_path,
                media_type="application/pdf",
                filename=f"{file_hash}_report.pdf"
            )
        
        raise HTTPException(status_code=404, detail="PDF not available")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
