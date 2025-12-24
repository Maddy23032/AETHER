"""Scan and vulnerability data models."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Scan job status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OWASPCategory(str, Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


class ScanConfig(BaseModel):
    """Configuration options for a scan."""
    
    deep_crawl: bool = Field(
        default=True,
        description="Enable deep crawling to discover more endpoints",
    )
    max_depth: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum crawl depth",
    )
    subdomain_enum: bool = Field(
        default=False,
        description="Enable subdomain enumeration",
    )
    api_discovery: bool = Field(
        default=False,
        description="Enable API endpoint discovery",
    )
    rate_limit_ms: int = Field(
        default=500,
        ge=100,
        le=5000,
        description="Delay between requests in milliseconds",
    )
    
    # Detection modules to enable - OWASP Top 10 2021
    # A01 - Broken Access Control
    enable_broken_access: bool = Field(default=True, description="Broken Access Control detection (IDOR, privilege escalation)")
    # A02 - Cryptographic Failures
    enable_crypto_failures: bool = Field(default=True, description="Cryptographic Failures detection (weak crypto, missing HTTPS)")
    # A03 - Injection
    enable_sqli: bool = Field(default=True, description="SQL Injection detection")
    enable_xss: bool = Field(default=True, description="Cross-Site Scripting detection")
    # A04 - Insecure Design
    enable_insecure_design: bool = Field(default=True, description="Insecure Design detection (business logic flaws)")
    # A05 - Security Misconfiguration
    enable_security_misconfig: bool = Field(default=True, description="Security Misconfiguration detection")
    # A06 - Vulnerable Components
    enable_vulnerable_components: bool = Field(default=True, description="Vulnerable and Outdated Components detection")
    # A07 - Authentication Failures
    enable_auth_failures: bool = Field(default=True, description="Authentication Failures detection")
    # A08 - Data Integrity Failures
    enable_data_integrity: bool = Field(default=True, description="Software and Data Integrity Failures detection")
    # A09 - Logging Failures
    enable_logging_failures: bool = Field(default=True, description="Security Logging and Monitoring Failures detection")
    # A10 - SSRF
    enable_ssrf: bool = Field(default=True, description="Server-Side Request Forgery detection")
    # Additional detectors
    enable_path_traversal: bool = Field(default=True, description="Path Traversal detection")
    enable_sensitive_data: bool = Field(default=True, description="Sensitive Data Exposure detection")
    
    # Authentication (Phase 2 feature)
    auth_type: Optional[str] = Field(default=None, description="Authentication type: none, basic, bearer, cookie")
    auth_credentials: Optional[Dict[str, str]] = Field(default=None, description="Authentication credentials")


class DiscoveredEndpoint(BaseModel):
    """An endpoint discovered during crawling."""
    
    url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Vulnerability(BaseModel):
    """A discovered security vulnerability."""
    
    id: str
    name: str
    severity: SeverityLevel
    owasp_category: OWASPCategory
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    evidence: str = Field(description="Technical evidence of the vulnerability")
    description: str = Field(description="Human-readable description")
    remediation: str = Field(description="Suggested fix")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")
    
    # For AI enrichment
    ai_analysis: Optional[str] = Field(default=None, description="AI-generated detailed analysis")
    
    # Metadata
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    detector_name: str = Field(description="Name of the detection plugin")
    
    # Request/Response for reproduction
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None


class ScanJob(BaseModel):
    """A scan job tracking record."""
    
    id: str
    target_url: str
    status: ScanStatus
    config: ScanConfig = Field(default_factory=ScanConfig)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    endpoints_discovered: int = 0
    endpoints_scanned: int = 0
    vulnerabilities_found: int = 0
    
    error_message: Optional[str] = None
    
    # Progress tracking
    current_phase: str = "pending"
    progress_percentage: float = 0.0


class ScanResult(BaseModel):
    """Complete results of a finished scan."""
    
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    
    # Summary statistics
    total_endpoints: int
    total_vulnerabilities: int
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    owasp_counts: Dict[str, int] = Field(default_factory=dict)
    
    # Detailed findings
    endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    
    # Scan metadata
    config_used: ScanConfig
    scanner_version: str = "0.1.0"
    
    def to_rag_format(self) -> "RAGDocument":
        """Convert scan results to RAG-optimized format for embedding."""
        
        # Create chunked content for embedding
        chunks = []
        
        # Summary chunk
        summary = f"""
Security Scan Summary for {self.target_url}
Scan Date: {self.completed_at.isoformat()}
Duration: {self.duration_seconds:.2f} seconds
Total Endpoints Discovered: {self.total_endpoints}
Total Vulnerabilities Found: {self.total_vulnerabilities}

Severity Distribution:
- Critical: {self.severity_counts.get('critical', 0)}
- High: {self.severity_counts.get('high', 0)}
- Medium: {self.severity_counts.get('medium', 0)}
- Low: {self.severity_counts.get('low', 0)}
- Info: {self.severity_counts.get('info', 0)}
"""
        chunks.append({
            "content": summary.strip(),
            "metadata": {
                "type": "summary",
                "scan_id": self.scan_id,
                "target": self.target_url,
            }
        })
        
        # Individual vulnerability chunks
        for vuln in self.vulnerabilities:
            vuln_text = f"""
Vulnerability: {vuln.name}
Severity: {vuln.severity.value.upper()}
OWASP Category: {vuln.owasp_category.value}
Endpoint: {vuln.method} {vuln.endpoint}
Parameter: {vuln.parameter or 'N/A'}

Description:
{vuln.description}

Evidence:
{vuln.evidence}

Remediation:
{vuln.remediation}

{f'AI Analysis: {vuln.ai_analysis}' if vuln.ai_analysis else ''}
"""
            chunks.append({
                "content": vuln_text.strip(),
                "metadata": {
                    "type": "vulnerability",
                    "scan_id": self.scan_id,
                    "target": self.target_url,
                    "severity": vuln.severity.value,
                    "owasp": vuln.owasp_category.value,
                    "endpoint": vuln.endpoint,
                    "vuln_id": vuln.id,
                }
            })
        
        # Endpoint inventory chunk
        endpoints_text = "Discovered Endpoints:\n"
        for ep in self.endpoints[:50]:  # Limit to prevent too-large chunks
            params = ", ".join(ep.parameters) if ep.parameters else "none"
            endpoints_text += f"- {ep.method} {ep.url} (params: {params})\n"
        
        chunks.append({
            "content": endpoints_text.strip(),
            "metadata": {
                "type": "endpoints",
                "scan_id": self.scan_id,
                "target": self.target_url,
            }
        })
        
        return RAGDocument(
            scan_id=self.scan_id,
            target_url=self.target_url,
            chunks=chunks,
            total_chunks=len(chunks),
        )


class RAGDocument(BaseModel):
    """Document format optimized for RAG ingestion."""
    
    scan_id: str
    target_url: str
    chunks: List[Dict[str, Any]]
    total_chunks: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
