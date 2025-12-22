"""Detection plugins package."""

from typing import List
from app.plugins.base import BaseDetector
from app.plugins.sqli import SQLiDetector
from app.plugins.xss import XSSDetector
from app.plugins.ssrf import SSRFDetector
from app.plugins.path_traversal import PathTraversalDetector
from app.plugins.security_misconfig import SecurityMisconfigDetector
from app.plugins.sensitive_data import SensitiveDataDetector
from app.models.scan import ScanConfig


def get_enabled_plugins(config: ScanConfig) -> List[BaseDetector]:
    """Return list of enabled detection plugins based on scan config."""
    plugins = []
    
    if config.enable_sqli:
        plugins.append(SQLiDetector())
    if config.enable_xss:
        plugins.append(XSSDetector())
    if config.enable_ssrf:
        plugins.append(SSRFDetector())
    if config.enable_path_traversal:
        plugins.append(PathTraversalDetector())
    if config.enable_security_misconfig:
        plugins.append(SecurityMisconfigDetector())
    if config.enable_sensitive_data:
        plugins.append(SensitiveDataDetector())
    
    return plugins


__all__ = [
    "BaseDetector",
    "SQLiDetector", 
    "XSSDetector",
    "SSRFDetector",
    "PathTraversalDetector",
    "SecurityMisconfigDetector",
    "SensitiveDataDetector",
    "get_enabled_plugins",
]
