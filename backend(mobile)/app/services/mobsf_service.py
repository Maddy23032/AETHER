"""
MobSF Service - Core integration with MobSF API
Handles API key scraping and all MobSF operations
Based on Mobile-Sec/MobSF_Auto.py
"""
import httpx
import os
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from app.config import get_settings

settings = get_settings()


class MobSFService:
    """
    MobSF API Service with automatic API key management.
    The API key is scraped from MobSF web interface since it changes on each Docker restart.
    """
    
    def __init__(self):
        self.base_url = settings.mobsf_url.rstrip("/")
        self._api_key: Optional[str] = None
        self._key_fetched_at: Optional[datetime] = None
        self._key_ttl = timedelta(minutes=30)  # Refresh key every 30 min
    
    async def get_api_key(self, force_refresh: bool = False) -> str:
        """
        Get MobSF API key, fetching via web scraping if needed.
        The key changes on every Docker container restart.
        """
        # Check if we need to refresh
        if not force_refresh and self._api_key and self._key_fetched_at:
            if datetime.utcnow() - self._key_fetched_at < self._key_ttl:
                return self._api_key
        
        # Fetch new key via web scraping
        self._api_key = await self._scrape_api_key()
        self._key_fetched_at = datetime.utcnow()
        return self._api_key
    
    async def _scrape_api_key(self) -> str:
        """
        Scrape API key from MobSF by logging in and accessing api_docs page.
        Based on Mobile-Sec/MobSF_Auto.py get_mobsf_api_key()
        """
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            # Step 1: Login to MobSF
            login_url = f"{self.base_url}/login/"
            login_data = {
                "username": settings.mobsf_username,
                "password": settings.mobsf_password
            }
            
            response = await client.post(login_url, data=login_data)
            
            if "Please enter a correct username and password" in response.text:
                raise Exception("MobSF login failed - check credentials")
            
            # Step 2: Get API docs page where key is displayed
            api_docs_url = f"{self.base_url}/api_docs"
            response = await client.get(api_docs_url)
            
            if response.status_code != 200:
                # Fallback to home page
                response = await client.get(f"{self.base_url}/home/")
                if response.status_code != 200:
                    raise Exception("Failed to access MobSF pages")
            
            # Step 3: Parse API key from HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # MobSF shows API key in <code> or <kbd> tag
            api_key_tag = soup.find("code") or soup.find("kbd")
            
            if not api_key_tag:
                raise Exception("API key element not found on page")
            
            api_key = api_key_tag.text.strip()
            
            if not api_key or len(api_key) < 10:
                raise Exception(f"Invalid API key format: {api_key}")
            
            print(f"[+] MobSF API Key obtained: {api_key[:8]}...")
            return api_key
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get headers with current API key."""
        if not self._api_key:
            raise Exception("API key not initialized - call get_api_key() first")
        return {"X-Mobsf-Api-Key": self._api_key}
    
    async def is_ready(self) -> bool:
        """Check if MobSF is accessible."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.base_url}/login/")
                return response.status_code == 200
        except Exception:
            return False
    
    async def upload_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Upload APK/IPA file to MobSF.
        Returns: {"hash": "...", "file_name": "...", "scan_type": "..."}
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f, "application/octet-stream")}
                response = await client.post(
                    f"{self.base_url}/api/v1/upload",
                    headers=self.headers,
                    files=files
                )
            
            if response.status_code != 200:
                raise Exception(f"Upload failed: {response.text}")
            
            data = response.json()
            
            if "error" in data:
                raise Exception(f"Upload error: {data['error']}")
            
            return data
    
    async def run_scan(self, file_hash: str) -> Dict[str, Any]:
        """
        Run static analysis scan on uploaded file.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/scan",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            if response.status_code != 200:
                raise Exception(f"Scan failed: {response.text}")
            
            return response.json()
    
    async def get_json_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Fetch JSON report for scanned file.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/report_json",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get report: {response.text}")
            
            return response.json()
    
    async def get_scorecard(self, file_hash: str) -> Dict[str, Any]:
        """
        Fetch scorecard for scanned file.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/scorecard",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get scorecard: {response.text}")
            
            return response.json()
    
    async def get_scan_logs(self, file_hash: str) -> Dict[str, Any]:
        """
        Fetch scan logs for file.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/scan_logs",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get logs: {response.text}")
            
            return response.json()
    
    async def download_pdf(self, file_hash: str, output_path: str) -> bool:
        """
        Download PDF report.
        Returns True if successful.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/download_pdf",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            if response.status_code != 200:
                print(f"[-] PDF download failed: {response.status_code}")
                return False
            
            with open(output_path, "wb") as f:
                f.write(response.content)
            
            return True
    
    async def delete_scan(self, file_hash: str) -> Dict[str, Any]:
        """
        Delete a scan from MobSF.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/delete_scan",
                headers=self.headers,
                data={"hash": file_hash}
            )
            
            return response.json()
    
    async def get_recent_scans(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """
        Get list of recent scans.
        """
        await self.get_api_key()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/api/v1/scans",
                headers=self.headers,
                params={"page": page, "page_size": page_size}
            )
            
            if response.status_code != 200:
                return {"content": []}
            
            return response.json()


# Singleton instance
_mobsf_service: Optional[MobSFService] = None


def get_mobsf_service() -> MobSFService:
    """Get singleton MobSF service instance."""
    global _mobsf_service
    if _mobsf_service is None:
        _mobsf_service = MobSFService()
    return _mobsf_service
