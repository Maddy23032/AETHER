"""Scanner orchestrator - coordinates crawling and detection plugins."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

import structlog

from app.config import get_settings
from app.models.scan import (
    DiscoveredEndpoint,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
)
from app.services.crawler import Crawler
from app.services.http_client import HttpClient
from app.plugins import get_enabled_plugins
from app.routers.websocket import get_connection_manager

logger = structlog.get_logger()
settings = get_settings()


class ScannerOrchestrator:
    """
    Main scanner orchestrator that coordinates:
    1. Crawling/endpoint discovery
    2. Running detection plugins against discovered endpoints
    3. Aggregating and formatting results
    4. Streaming progress via WebSocket
    """

    def __init__(self, scan_id: str, target_url: str, config: ScanConfig):
        self.scan_id = scan_id
        self.target_url = target_url
        self.config = config
        self.ws_manager = get_connection_manager()
        
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints: List[DiscoveredEndpoint] = []
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

    async def _log(self, log_type: str, message: str):
        """Send log message to WebSocket clients and logger."""
        await self.ws_manager.send_log(self.scan_id, log_type, message)
        
        log_method = getattr(logger, log_type if log_type != "ok" else "info")
        log_method(message, scan_id=self.scan_id)

    async def _update_progress(self, current: int, total: int, phase: str):
        """Send progress update to WebSocket clients."""
        await self.ws_manager.send_progress(self.scan_id, current, total, phase)

    async def _report_finding(self, vuln: Vulnerability):
        """Report a new vulnerability finding."""
        self.vulnerabilities.append(vuln)
        await self.ws_manager.send_finding(self.scan_id, vuln.model_dump(mode="json"))
        await self._log("critical" if vuln.severity == SeverityLevel.CRITICAL else "warn", 
                       f"Found {vuln.severity.value.upper()}: {vuln.name} at {vuln.endpoint}")

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        self.started_at = datetime.utcnow()
        
        await self.ws_manager.send_status(self.scan_id, "running")
        await self._log("info", f"Starting scan of {self.target_url}")
        
        try:
            # Phase 1: Discovery/Crawling
            await self._log("info", "Phase 1: Discovering endpoints...")
            await self._update_progress(0, 100, "discovery")
            
            async with HttpClient(
                self.target_url,
                rate_limit_ms=self.config.rate_limit_ms,
            ) as http_client:
                
                # Run crawler
                crawler = Crawler(
                    base_url=self.target_url,
                    config=self.config,
                    http_client=http_client,
                    on_endpoint_found=self._on_endpoint_discovered,
                )
                
                self.endpoints = await crawler.crawl()
                
                await self._log("ok", f"Discovery complete: {len(self.endpoints)} endpoints found")
                await self._update_progress(30, 100, "discovery")
                
                # Phase 2: Vulnerability Detection
                await self._log("info", "Phase 2: Running vulnerability detection...")
                
                plugins = get_enabled_plugins(self.config)
                await self._log("info", f"Loaded {len(plugins)} detection plugins")
                
                total_checks = len(self.endpoints) * len(plugins)
                checks_completed = 0
                
                for endpoint in self.endpoints:
                    for plugin in plugins:
                        try:
                            findings = await plugin.detect(endpoint, http_client)
                            
                            for finding in findings:
                                await self._report_finding(finding)
                            
                        except Exception as e:
                            await self._log("warn", f"Plugin {plugin.name} error: {str(e)}")
                        
                        checks_completed += 1
                        progress = 30 + int((checks_completed / total_checks) * 60)
                        await self._update_progress(progress, 100, "detection")
                
                await self._log("ok", "Vulnerability detection complete")
                await self._update_progress(90, 100, "detection")
                
                # Phase 3: Finalization
                await self._log("info", "Phase 3: Generating report...")
                
                self.completed_at = datetime.utcnow()
                duration = (self.completed_at - self.started_at).total_seconds()
                
                # Calculate severity counts
                severity_counts = {}
                for vuln in self.vulnerabilities:
                    sev = vuln.severity.value
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                # Calculate OWASP category counts
                owasp_counts = {}
                for vuln in self.vulnerabilities:
                    cat = vuln.owasp_category.value
                    owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
                
                result = ScanResult(
                    scan_id=self.scan_id,
                    target_url=self.target_url,
                    started_at=self.started_at,
                    completed_at=self.completed_at,
                    duration_seconds=duration,
                    total_endpoints=len(self.endpoints),
                    total_vulnerabilities=len(self.vulnerabilities),
                    severity_counts=severity_counts,
                    owasp_counts=owasp_counts,
                    endpoints=self.endpoints,
                    vulnerabilities=self.vulnerabilities,
                    config_used=self.config,
                )
                
                await self._log("ok", f"Scan complete! Found {len(self.vulnerabilities)} vulnerabilities in {duration:.1f}s")
                await self._update_progress(100, 100, "complete")
                await self.ws_manager.send_status(self.scan_id, "completed")
                
                return result
                
        except Exception as e:
            await self._log("critical", f"Scan failed: {str(e)}")
            await self.ws_manager.send_status(self.scan_id, "failed")
            raise

    async def _on_endpoint_discovered(self, endpoint: DiscoveredEndpoint):
        """Callback when crawler discovers a new endpoint."""
        await self._log("info", f"Discovered: {endpoint.method} {endpoint.url}")
