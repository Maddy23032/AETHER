"""Data models for scans and vulnerabilities."""

from app.models.scan import (
    ScanConfig,
    ScanJob,
    ScanResult,
    ScanStatus,
    Vulnerability,
    SeverityLevel,
    OWASPCategory,
    DiscoveredEndpoint,
    RAGDocument,
)

__all__ = [
    "ScanConfig",
    "ScanJob",
    "ScanResult",
    "ScanStatus",
    "Vulnerability",
    "SeverityLevel",
    "OWASPCategory",
    "DiscoveredEndpoint",
    "RAGDocument",
]
