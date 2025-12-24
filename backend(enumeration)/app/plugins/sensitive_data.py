"""Sensitive Data Exposure detection plugin - Enhanced version."""

import re
from typing import List, Optional, Tuple
from uuid import uuid4
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Comprehensive patterns for sensitive data detection
SENSITIVE_PATTERNS = {
    # Credentials and secrets
    "credentials": [
        (r"password\s*[=:]\s*['\"]?([^'\"<>\s]{4,})['\"]?", "Password in Response", SeverityLevel.CRITICAL),
        (r"passwd\s*[=:]\s*['\"]?([^'\"<>\s]{4,})['\"]?", "Password in Response", SeverityLevel.CRITICAL),
        (r"pwd\s*[=:]\s*['\"]?([^'\"<>\s]{4,})['\"]?", "Password Value", SeverityLevel.HIGH),
        (r"secret\s*[=:]\s*['\"]?([^'\"<>\s]{8,})['\"]?", "Secret Value Exposed", SeverityLevel.CRITICAL),
    ],
    # API Keys and Tokens
    "api_keys": [
        (r"api[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Key Exposed", SeverityLevel.HIGH),
        (r"apikey\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Key Exposed", SeverityLevel.HIGH),
        (r"api[_-]?secret\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Secret Exposed", SeverityLevel.CRITICAL),
        (r"access[_-]?token\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", "Access Token Exposed", SeverityLevel.CRITICAL),
        (r"auth[_-]?token\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", "Auth Token Exposed", SeverityLevel.CRITICAL),
        (r"bearer\s+([a-zA-Z0-9_\-\.]{20,})", "Bearer Token Exposed", SeverityLevel.CRITICAL),
    ],
    # Cloud Provider Keys
    "cloud_keys": [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", SeverityLevel.CRITICAL),
        (r"aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", "AWS Secret Key", SeverityLevel.CRITICAL),
        (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", SeverityLevel.HIGH),
        (r"ya29\.[0-9A-Za-z_-]+", "Google OAuth Token", SeverityLevel.HIGH),
        (r"[a-z0-9]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", SeverityLevel.MEDIUM),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", SeverityLevel.CRITICAL),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", SeverityLevel.CRITICAL),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token", SeverityLevel.CRITICAL),
        (r"glpat-[a-zA-Z0-9_-]{20}", "GitLab Personal Access Token", SeverityLevel.CRITICAL),
        (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "Slack Token", SeverityLevel.HIGH),
    ],
    # Private Keys
    "private_keys": [
        (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", SeverityLevel.CRITICAL),
        (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key", SeverityLevel.CRITICAL),
        (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key", SeverityLevel.CRITICAL),
        (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key", SeverityLevel.CRITICAL),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", SeverityLevel.CRITICAL),
        (r"-----BEGIN PRIVATE KEY-----", "Private Key", SeverityLevel.CRITICAL),
    ],
    # Database Connection Strings
    "database": [
        (r"mongodb(\+srv)?://[^'\"<>\s]+", "MongoDB Connection String", SeverityLevel.CRITICAL),
        (r"postgres(ql)?://[^'\"<>\s]+", "PostgreSQL Connection String", SeverityLevel.CRITICAL),
        (r"mysql://[^'\"<>\s]+", "MySQL Connection String", SeverityLevel.CRITICAL),
        (r"mssql://[^'\"<>\s]+", "MSSQL Connection String", SeverityLevel.CRITICAL),
        (r"redis://[^'\"<>\s]+", "Redis Connection String", SeverityLevel.HIGH),
        (r"amqp://[^'\"<>\s]+", "RabbitMQ Connection String", SeverityLevel.HIGH),
    ],
    # Personal Data (PII)
    "pii": [
        (r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number (SSN)", SeverityLevel.CRITICAL),
        (r"\b\d{9}\b", "Possible SSN (9 digits)", SeverityLevel.MEDIUM),
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa Card Number", SeverityLevel.CRITICAL),
        (r"\b5[1-5][0-9]{14}\b", "MasterCard Number", SeverityLevel.CRITICAL),
        (r"\b3[47][0-9]{13}\b", "American Express Card", SeverityLevel.CRITICAL),
        (r"\b6(?:011|5[0-9]{2})[0-9]{12}\b", "Discover Card Number", SeverityLevel.CRITICAL),
        (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "IBAN Number", SeverityLevel.HIGH),
    ],
    # JWT Tokens (check if leaked in response)
    "jwt": [
        (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT Token Exposed", SeverityLevel.HIGH),
    ],
    # Internal Paths/Info
    "internal": [
        (r"(?:/home/[a-zA-Z0-9_-]+|/var/www|/opt/[a-zA-Z0-9_-]+|C:\\\\Users\\\\[a-zA-Z0-9_-]+)", "Internal Path Disclosure", SeverityLevel.LOW),
        (r"(?:stack\s*trace|traceback|exception\s+in|error\s+at\s+line)", "Stack Trace Exposed", SeverityLevel.MEDIUM),
    ],
}

# Patterns that might be false positives in certain contexts
FALSE_POSITIVE_CONTEXTS = [
    "example.com", "test@", "user@example", "your-api-key", 
    "YOUR_", "xxx", "***", "placeholder", "sample",
    "documentation", "tutorial", "<script", "function",
]


class SensitiveDataDetector(BaseDetector):
    """Enhanced Sensitive Data Exposure detector."""

    name = "Sensitive Data Detector"
    description = "Detects exposed credentials, API keys, PII, and sensitive configuration"

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            response = await http_client.get(endpoint.url)
            content = response.text
            
            # Skip very large responses to avoid performance issues
            if len(content) > 500000:  # 500KB limit
                content = content[:500000]
            
            # Check each category of sensitive patterns
            for category, patterns in SENSITIVE_PATTERNS.items():
                for pattern, name, severity in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    
                    if matches:
                        # Filter out false positives
                        real_matches = self._filter_false_positives(matches, content)
                        
                        if real_matches:
                            vuln = self._create_vulnerability(
                                endpoint.url,
                                category,
                                name,
                                severity,
                                real_matches,
                            )
                            vulnerabilities.append(vuln)
            
            # Check response headers for sensitive data
            header_vulns = self._check_headers(endpoint.url, response.headers)
            vulnerabilities.extend(header_vulns)
            
            # Check for HTTP in sensitive contexts
            http_vulns = self._check_insecure_references(endpoint.url, content)
            vulnerabilities.extend(http_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities

    def _filter_false_positives(
        self, 
        matches: List[str], 
        content: str
    ) -> List[str]:
        """Filter out likely false positive matches."""
        filtered = []
        content_lower = content.lower()
        
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match else ""
            
            match_str = str(match).lower()
            
            # Skip if it looks like a placeholder or example
            is_false_positive = False
            for fp in FALSE_POSITIVE_CONTEXTS:
                if fp.lower() in match_str:
                    is_false_positive = True
                    break
            
            # Skip if all same character (like xxxx or ****)
            if len(set(match_str)) <= 2:
                is_false_positive = True
            
            if not is_false_positive:
                filtered.append(match)
        
        return filtered

    def _create_vulnerability(
        self,
        url: str,
        category: str,
        name: str,
        severity: SeverityLevel,
        matches: List[str],
    ) -> Vulnerability:
        """Create a vulnerability record for sensitive data exposure."""
        # Redact actual sensitive values in evidence
        redacted_matches = []
        for m in matches[:3]:  # Limit to first 3 matches
            if isinstance(m, tuple):
                m = m[0]
            if len(str(m)) > 10:
                redacted = f"{str(m)[:4]}...{str(m)[-4:]}"
            else:
                redacted = f"{str(m)[:2]}***"
            redacted_matches.append(redacted)
        
        return Vulnerability(
            id=str(uuid4()),
            name=name,
            severity=severity,
            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            endpoint=url,
            method="GET",
            parameter=None,
            evidence=f"Found {len(matches)} instance(s). Examples: {', '.join(redacted_matches)}",
            description=self._get_description(category, name),
            remediation=self._get_remediation(category),
            confidence=0.85,
            detector_name=self.name,
        )

    def _check_headers(
        self, 
        url: str, 
        headers: dict
    ) -> List[Vulnerability]:
        """Check response headers for sensitive data leakage."""
        vulnerabilities = []
        
        # Check for sensitive headers
        sensitive_header_patterns = [
            ("Authorization", r".+", "Authorization Header in Response", SeverityLevel.HIGH),
            ("Set-Cookie", r"password|token|secret", "Sensitive Cookie Value", SeverityLevel.HIGH),
        ]
        
        for header, pattern, name, severity in sensitive_header_patterns:
            value = headers.get(header, "")
            if value and re.search(pattern, value, re.I):
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name=name,
                    severity=severity,
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    endpoint=url,
                    method="GET",
                    parameter=None,
                    evidence=f"Header: {header}",
                    description=f"Sensitive data found in {header} header",
                    remediation="Remove sensitive data from response headers",
                    confidence=0.90,
                    detector_name=self.name,
                ))
        
        return vulnerabilities

    def _check_insecure_references(
        self, 
        url: str, 
        content: str
    ) -> List[Vulnerability]:
        """Check for insecure (HTTP) references to sensitive resources."""
        vulnerabilities = []
        
        if url.startswith("https://"):
            # Check for mixed content
            http_refs = re.findall(r'(http://[^"\'>\s]+)', content, re.I)
            sensitive_http = [
                ref for ref in http_refs 
                if any(s in ref.lower() for s in ["api", "auth", "login", "secure", "token"])
            ]
            
            if sensitive_http:
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name="Mixed Content - Sensitive HTTP References",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    endpoint=url,
                    method="GET",
                    parameter=None,
                    evidence=f"Found {len(sensitive_http)} HTTP references on HTTPS page",
                    description="HTTPS page references sensitive resources over insecure HTTP",
                    remediation="Update all references to use HTTPS",
                    confidence=0.80,
                    detector_name=self.name,
                ))
        
        return vulnerabilities

    def _get_description(self, category: str, name: str) -> str:
        """Get detailed description based on data category."""
        descriptions = {
            "credentials": f"{name} detected in response. Passwords and credentials should never appear in HTTP responses.",
            "api_keys": f"{name}. API keys should be kept server-side and never exposed to clients.",
            "cloud_keys": f"{name}. Cloud provider credentials can lead to full infrastructure compromise.",
            "private_keys": f"{name}. Private keys should never be transmitted or exposed in responses.",
            "database": f"{name}. Database connection strings contain credentials and should not be exposed.",
            "pii": f"{name}. Personal identifiable information exposure may violate privacy regulations (GDPR, CCPA).",
            "jwt": f"{name}. JWT tokens in responses may be leaked or logged, compromising user sessions.",
            "internal": f"{name}. Internal paths and stack traces help attackers understand the application structure.",
        }
        return descriptions.get(category, f"{name} detected in response")

    def _get_remediation(self, category: str) -> str:
        """Get remediation advice based on data category."""
        remediations = {
            "credentials": "Never include passwords in responses. Use secure session tokens instead.",
            "api_keys": "Store API keys server-side. Use environment variables. Rotate compromised keys immediately.",
            "cloud_keys": "Rotate compromised cloud credentials immediately. Use IAM roles instead of keys where possible.",
            "private_keys": "Never transmit private keys. Regenerate key pairs if exposed.",
            "database": "Move connection strings to environment variables. Never expose to frontend.",
            "pii": "Minimize PII collection. Mask sensitive data in responses. Implement data access controls.",
            "jwt": "Don't log tokens. Use short expiration times. Implement token refresh mechanism.",
            "internal": "Disable debug mode in production. Use custom error pages. Configure proper logging.",
        }
        return remediations.get(category, "Remove sensitive data from responses")
