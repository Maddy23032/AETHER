"""
Supabase Service for Intelligence Backend
Handles fetching scan data from Supabase for RAG ingestion
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from supabase import create_client, Client


class SupabaseService:
    """Service for interacting with Supabase to fetch scan data"""
    
    def __init__(self):
        self._client: Optional[Client] = None
    
    @property
    def client(self) -> Client:
        """Lazy initialize Supabase client"""
        if self._client is None:
            url = os.getenv("SUPABASE_URL")
            key = os.getenv("SUPABASE_ANON_KEY")
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_ANON_KEY must be set")
            
            self._client = create_client(url, key)
        
        return self._client
    
    async def get_all_recon_scans(self) -> List[Dict[str, Any]]:
        """Fetch all recon scans with their findings and results"""
        try:
            # Get all recon scans
            scans_response = self.client.table("scans").select("*").eq("scan_type", "recon").order("created_at", desc=True).execute()
            scans = scans_response.data or []
            
            result = []
            for scan in scans:
                scan_id = scan.get("id")
                
                # Get findings for this scan
                findings_response = self.client.table("recon_findings").select("*").eq("scan_id", scan_id).execute()
                findings = findings_response.data or []
                
                # Get results for this scan
                results_response = self.client.table("recon_results").select("*").eq("scan_id", scan_id).execute()
                results = results_response.data or []
                
                result.append({
                    "scan": scan,
                    "findings": findings,
                    "results": results
                })
            
            print(f"[Supabase] Fetched {len(result)} recon scans")
            return result
        except Exception as e:
            print(f"[Supabase] Error fetching recon scans: {e}")
            return []
    
    async def get_all_enum_scans(self) -> List[Dict[str, Any]]:
        """Fetch all enumeration scans with their vulnerabilities"""
        try:
            # Get all enumeration scans
            scans_response = self.client.table("scans").select("*").eq("scan_type", "enumeration").order("created_at", desc=True).execute()
            scans = scans_response.data or []
            
            result = []
            for scan in scans:
                scan_id = scan.get("id")
                
                # Get vulnerabilities for this scan
                vulns_response = self.client.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
                vulnerabilities = vulns_response.data or []
                
                result.append({
                    "scan": scan,
                    "vulnerabilities": vulnerabilities
                })
            
            print(f"[Supabase] Fetched {len(result)} enumeration scans")
            return result
        except Exception as e:
            print(f"[Supabase] Error fetching enumeration scans: {e}")
            return []
    
    async def get_all_mobile_scans(self) -> List[Dict[str, Any]]:
        """Fetch all mobile scans"""
        try:
            response = self.client.table("mobile_scans").select("*").order("created_at", desc=True).execute()
            scans = response.data or []
            
            print(f"[Supabase] Fetched {len(scans)} mobile scans")
            return scans
        except Exception as e:
            print(f"[Supabase] Error fetching mobile scans: {e}")
            return []
    
    async def get_scan_counts(self) -> Dict[str, int]:
        """Get counts of each scan type"""
        try:
            recon_count = len(self.client.table("scans").select("id").eq("scan_type", "recon").execute().data or [])
            enum_count = len(self.client.table("scans").select("id").eq("scan_type", "enumeration").execute().data or [])
            
            try:
                mobile_count = len(self.client.table("mobile_scans").select("id").execute().data or [])
            except:
                mobile_count = 0
            
            return {
                "recon": recon_count,
                "enum": enum_count,
                "mobile": mobile_count
            }
        except Exception as e:
            print(f"[Supabase] Error getting scan counts: {e}")
            return {"recon": 0, "enum": 0, "mobile": 0}


# Global instance
supabase_service = SupabaseService()
