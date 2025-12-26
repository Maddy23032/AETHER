"""Detection plugins package."""

from typing import List
from app.plugins.base import BaseDetector
from app.plugins.sqli import SQLiDetector
from app.plugins.xss import XSSDetector
from app.plugins.ssrf import SSRFDetector
from app.plugins.path_traversal import PathTraversalDetector
from app.plugins.security_misconfig import SecurityMisconfigDetector
from app.plugins.sensitive_data import SensitiveDataDetector
from app.plugins.broken_access import BrokenAccessControlDetector
from app.plugins.crypto_failures import CryptoFailuresDetector
from app.plugins.insecure_design import InsecureDesignDetector
from app.plugins.vulnerable_components import VulnerableComponentsDetector
from app.plugins.auth_failures import AuthFailuresDetector
from app.plugins.data_integrity import DataIntegrityDetector
from app.plugins.logging_failures import LoggingFailuresDetector
from app.models.scan import ScanConfig


def get_enabled_plugins(config: ScanConfig) -> List[BaseDetector]:
    """Return list of enabled detection plugins based on scan config."""
    plugins = []
    
    # A01 - Broken Access Control
    if config.enable_broken_access:
        plugins.append(BrokenAccessControlDetector())
    # A02 - Cryptographic Failures
    if config.enable_crypto_failures:
        plugins.append(CryptoFailuresDetector())
    # A03 - Injection (SQLi, XSS)
    if config.enable_sqli:
        plugins.append(SQLiDetector())
    if config.enable_xss:
        plugins.append(XSSDetector())
    # A04 - Insecure Design
    if config.enable_insecure_design:
        plugins.append(InsecureDesignDetector())
    # A05 - Security Misconfiguration
    if config.enable_security_misconfig:
        plugins.append(SecurityMisconfigDetector())
    # A06 - Vulnerable Components
    if config.enable_vulnerable_components:
        plugins.append(VulnerableComponentsDetector())
    # A07 - Authentication Failures
    if config.enable_auth_failures:
        plugins.append(AuthFailuresDetector())
    # A08 - Data Integrity Failures
    if config.enable_data_integrity:
        plugins.append(DataIntegrityDetector())
    # A09 - Logging Failures
    if config.enable_logging_failures:
        plugins.append(LoggingFailuresDetector())
    # A10 - SSRF
    if config.enable_ssrf:
        plugins.append(SSRFDetector())
    # Additional detectors
    if config.enable_path_traversal:
        plugins.append(PathTraversalDetector())
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
    "BrokenAccessControlDetector",
    "CryptoFailuresDetector",
    "InsecureDesignDetector",
    "VulnerableComponentsDetector",
    "AuthFailuresDetector",
    "DataIntegrityDetector",
    "LoggingFailuresDetector",
    "get_enabled_plugins",
]
