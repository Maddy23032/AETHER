"""
HTML Scraper Service - Scrapes additional data from MobSF static analyzer page
Based on Mobile-Sec/ScrapeTest.py
"""
import httpx
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any, List

from app.config import get_settings

settings = get_settings()


class HTMLScraperService:
    """
    Scrapes detailed analysis data from MobSF's static analyzer HTML page.
    This provides additional data not available via the REST API:
    - Malware lookup links (VirusTotal, Triage, MetaDefender, Hybrid Analysis)
    - APKiD Analysis
    - Behaviour Analysis
    - Domain Malware Check
    - URLs found in APK
    - Emails found in APK
    """
    
    def __init__(self):
        self.base_url = settings.mobsf_url.rstrip("/")
    
    async def _login(self) -> httpx.AsyncClient:
        """Login to MobSF and return authenticated client."""
        client = httpx.AsyncClient(follow_redirects=True, timeout=60.0)
        
        login_url = f"{self.base_url}/login/"
        login_data = {
            "username": settings.mobsf_username,
            "password": settings.mobsf_password
        }
        
        response = await client.post(login_url, data=login_data)
        
        if "Please enter a correct username and password" in response.text:
            await client.aclose()
            raise Exception("Scraper login failed")
        
        return client
    
    async def scrape_static_analyzer(self, file_hash: str) -> Dict[str, Any]:
        """
        Scrape the static analyzer HTML page for additional data.
        Based on Mobile-Sec/ScrapeTest.py parse_mobsf_html_report()
        """
        client = await self._login()
        
        try:
            # Fetch the static analyzer page
            url = f"{self.base_url}/static_analyzer/{file_hash}/"
            response = await client.get(url)
            
            if response.status_code != 200:
                return {"error": f"Failed to fetch page: {response.status_code}"}
            
            return self._parse_html(response.text)
            
        finally:
            await client.aclose()
    
    def _parse_html(self, html_content: str) -> Dict[str, Any]:
        """
        Parse MobSF static analyzer HTML page.
        Directly based on Mobile-Sec/ScrapeTest.py
        """
        soup = BeautifulSoup(html_content, "html.parser")
        
        result = {
            "malware_lookup": {},
            "apkid_analysis": [],
            "behaviour_analysis": [],
            "domain_malware_check": [],
            "urls": [],
            "emails": []
        }
        
        def extract_table(section_id: str) -> List[Dict[str, str]]:
            """Extract table rows under given section id."""
            anchor = soup.find("a", {"id": section_id})
            if not anchor:
                return []
            
            table = anchor.find_next("table")
            if not table:
                return []
            
            headers = [h.get_text(strip=True).lower() for h in table.find_all("th")]
            rows = []
            
            for tr in table.find_all("tr")[1:]:
                cols = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
                if cols:
                    rows.append(dict(zip(headers, cols)))
            
            return rows
        
        # --- Malware Lookup Links ---
        malware_section = soup.find("a", {"id": "malware_lookup"})
        if malware_section:
            container = malware_section.find_next("section")
            if container:
                links = container.find_all("a", href=True)
                for link in links:
                    text = link.get_text(strip=True).lower()
                    href = link["href"]
                    if "virustotal" in text:
                        result["malware_lookup"]["virustotal"] = href
                    elif "triage" in text:
                        result["malware_lookup"]["triage"] = href
                    elif "metadefender" in text:
                        result["malware_lookup"]["metadefender"] = href
                    elif "hybrid" in text:
                        result["malware_lookup"]["hybrid_analysis"] = href
        
        # --- APKiD Analysis ---
        result["apkid_analysis"] = extract_table("apkid")
        
        # --- Behaviour Analysis ---
        result["behaviour_analysis"] = extract_table("behaviour")
        
        # --- Domain Malware Check ---
        result["domain_malware_check"] = extract_table("malware_check")
        
        # --- URLs ---
        result["urls"] = extract_table("urls")
        
        # --- Emails ---
        result["emails"] = extract_table("emails")
        
        return result
    
    async def get_plain_text_report(self, file_hash: str) -> str:
        """
        Get plain text version of the static analyzer page.
        Based on Mobile-Sec/ScrapeTest.py fetch_report_text()
        """
        client = await self._login()
        
        try:
            url = f"{self.base_url}/static_analyzer/{file_hash}/"
            response = await client.get(url)
            
            if response.status_code != 200:
                return ""
            
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.get_text(separator="\n", strip=True)
            
        finally:
            await client.aclose()


# Singleton instance
_scraper_service: Optional[HTMLScraperService] = None


def get_scraper_service() -> HTMLScraperService:
    """Get singleton scraper service instance."""
    global _scraper_service
    if _scraper_service is None:
        _scraper_service = HTMLScraperService()
    return _scraper_service
