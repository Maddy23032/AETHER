"""Cryptographic Failures detection plugin - OWASP A02:2021."""

import re
from typing import List, Optional, Dict, Any
from uuid import uuid4
from urllib.parse import urlparse
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Weak/deprecated cryptographic patterns
WEAK_CRYPTO_PATTERNS = {
    "md5": [
        r"[a-f0-9]{32}",  # MD5 hash pattern
        r"md5\s*\(", r"md5_hash", r"md5sum",
    ],
    "sha1": [
        r"[a-f0-9]{40}",  # SHA1 hash pattern
        r"sha1\s*\(", r"sha1_hash",
    ],
    "base64_credentials": [
        r"Basic\s+[A-Za-z0-9+/=]{10,}",  # Basic auth
        r"password[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=]{8,}[\"']",
    ],
}

# Sensitive data patterns that should be encrypted
SENSITIVE_DATA_PATTERNS = {
    "credit_card": [
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
        r"\b5[1-5][0-9]{14}\b",  # Mastercard
        r"\b3[47][0-9]{13}\b",  # Amex
        r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",  # Discover
    ],
    "ssn": [
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN format
    ],
    "api_key": [
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9]{20,}",
        r"apikey[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9]{20,}",
        r"secret[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9]{20,}",
    ],
    "private_key": [
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
    ],
    "aws_key": [
        r"AKIA[0-9A-Z]{16}",  # AWS Access Key
        r"aws[_-]?secret[_-]?access[_-]?key",
    ],
    "password_in_url": [
        r"[?&](?:password|passwd|pwd|pass)=([^&\s]{3,})",
    ],
}

# Required security headers for proper encryption
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "severity": SeverityLevel.MEDIUM,
        "description": "HSTS header is missing. This allows downgrade attacks to HTTP.",
        "required_directives": ["max-age"],
    },
    "content-security-policy": {
        "name": "Content Security Policy",
        "severity": SeverityLevel.LOW,
        "description": "CSP header is missing or weak. This increases XSS risk.",
        "check_upgrade_insecure": True,
    },
}

# TLS/SSL issues to check
TLS_ISSUES = [
    "ssl", "tls", "certificate", "https",
]


class CryptoFailuresDetector(BaseDetector):
    """Detects Cryptographic Failures (OWASP A02:2021)."""

    name = "Cryptographic Failures Detector"
    description = "Detects weak cryptography, missing encryption, insecure data transmission, and exposed secrets"

    def __init__(self):
        self.checked_hosts: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Check for HTTP (non-HTTPS) with sensitive forms
        vuln = await self._check_insecure_transport(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check security headers
        header_vulns = await self._check_security_headers(endpoint, http_client)
        vulnerabilities.extend(header_vulns)

        # Check for exposed sensitive data
        data_vulns = await self._check_exposed_data(endpoint, http_client)
        vulnerabilities.extend(data_vulns)

        # Check for weak cryptographic patterns
        crypto_vulns = await self._check_weak_crypto(endpoint, http_client)
        vulnerabilities.extend(crypto_vulns)

        # Check cookie security
        cookie_vulns = await self._check_cookie_security(endpoint, http_client)
        vulnerabilities.extend(cookie_vulns)

        # Check for mixed content
        vuln = await self._check_mixed_content(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_insecure_transport(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for sensitive data transmitted over HTTP."""
        parsed = urlparse(endpoint.url)
        
        # Only flag HTTP, not HTTPS
        if parsed.scheme != "http":
            return None

        # Check if there are sensitive forms on HTTP pages
        has_sensitive_form = False
        sensitive_fields = []
        
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                input_type = inp.get("type", "").lower()
                input_name = inp.get("name", "").lower()
                
                if input_type == "password":
                    has_sensitive_form = True
                    sensitive_fields.append("password")
                elif any(s in input_name for s in ["credit", "card", "ssn", "secret", "token"]):
                    has_sensitive_form = True
                    sensitive_fields.append(input_name)

        if has_sensitive_form:
            return Vulnerability(
                id=str(uuid4()),
                name="Sensitive Data Over Unencrypted Connection",
                severity=SeverityLevel.CRITICAL,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                endpoint=endpoint.url,
                method="GET",
                parameter=None,
                evidence=f"Page served over HTTP contains sensitive form fields: {', '.join(sensitive_fields)}. Data submitted will be transmitted in cleartext.",
                description="Sensitive data including passwords or financial information is being collected over an unencrypted HTTP connection. Attackers on the network can intercept this data.",
                remediation="Implement HTTPS across the entire application. Redirect all HTTP traffic to HTTPS. Use HSTS to prevent downgrade attacks.",
                confidence=0.98,
                detector_name=self.name,
            )

        return None

    async def _check_security_headers(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for missing or weak security headers."""
        vulnerabilities = []
        
        parsed = urlparse(endpoint.url)
        host = parsed.netloc
        
        # Only check once per host
        if host in self.checked_hosts:
            return []
        self.checked_hosts.add(host)

        try:
            response = await http_client.get(endpoint.url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check HSTS
            if "strict-transport-security" not in headers:
                if parsed.scheme == "https":
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Missing HSTS Header",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="Strict-Transport-Security header is missing from HTTPS response.",
                        description="The HTTP Strict Transport Security header is not set. This leaves users vulnerable to SSL stripping and downgrade attacks.",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to all HTTPS responses.",
                        confidence=0.95,
                        detector_name=self.name,
                    ))
            else:
                # Check HSTS max-age
                hsts = headers.get("strict-transport-security", "")
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Weak HSTS Configuration",
                            severity=SeverityLevel.LOW,
                            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence=f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended minimum is 1 year (31536000 seconds).",
                            description="The HSTS max-age is too short, reducing the effectiveness of the protection.",
                            remediation="Increase HSTS max-age to at least 31536000 (1 year). Consider adding includeSubDomains and preload directives.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

            # Check for secure cookie without Secure flag on HTTPS
            if parsed.scheme == "https":
                set_cookie = headers.get("set-cookie", "")
                if set_cookie and "secure" not in set_cookie.lower():
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Cookie Missing Secure Flag",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"Set-Cookie header does not include 'Secure' flag: {set_cookie[:100]}...",
                        description="Cookies are set without the Secure flag on an HTTPS site. These cookies could be sent over unencrypted connections.",
                        remediation="Add the 'Secure' flag to all cookies to ensure they are only transmitted over HTTPS.",
                        confidence=0.95,
                        detector_name=self.name,
                    ))

        except Exception:
            pass

        return vulnerabilities

    async def _check_exposed_data(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for exposed sensitive data in responses."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            for data_type, patterns in SENSITIVE_DATA_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        # Mask the sensitive data in evidence
                        masked_matches = [m[:4] + "****" + m[-4:] if len(m) > 8 else "****" for m in matches[:3]]
                        
                        severity = SeverityLevel.CRITICAL if data_type in ["credit_card", "private_key", "aws_key"] else SeverityLevel.HIGH
                        
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Exposed {data_type.replace('_', ' ').title()}",
                            severity=severity,
                            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence=f"Found {len(matches)} instance(s) of {data_type} pattern. Samples (masked): {masked_matches}",
                            description=f"Sensitive data ({data_type.replace('_', ' ')}) was found exposed in the response. This data should be encrypted or not exposed to clients.",
                            remediation=f"Remove or encrypt {data_type.replace('_', ' ')} data. Use proper access controls. Audit data exposure points.",
                            confidence=0.85 if data_type in ["api_key", "private_key"] else 0.70,
                            detector_name=self.name,
                        ))
                        break  # Only report once per data type per endpoint

        except Exception:
            pass

        return vulnerabilities

    async def _check_weak_crypto(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for weak cryptographic implementations."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Check for MD5 usage indicators
            md5_indicators = [
                r"md5\s*\(", r"md5_hash", r"MD5\s*=",
                r"algorithm[\"']?\s*[:=]\s*[\"']?md5",
            ]
            for pattern in md5_indicators:
                if re.search(pattern, text, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Weak Hashing Algorithm (MD5)",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="MD5 hashing algorithm reference found in response. MD5 is cryptographically broken.",
                        description="The application appears to use MD5 for hashing. MD5 is considered cryptographically broken and unsuitable for security purposes.",
                        remediation="Replace MD5 with secure alternatives like SHA-256, SHA-3, or bcrypt/scrypt/Argon2 for passwords.",
                        confidence=0.75,
                        detector_name=self.name,
                    ))
                    break

            # Check for SHA1 usage
            sha1_indicators = [
                r"sha1\s*\(", r"sha1_hash", r"SHA1\s*=",
                r"algorithm[\"']?\s*[:=]\s*[\"']?sha1",
            ]
            for pattern in sha1_indicators:
                if re.search(pattern, text, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Weak Hashing Algorithm (SHA1)",
                        severity=SeverityLevel.LOW,
                        owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="SHA1 hashing algorithm reference found in response. SHA1 has known collision vulnerabilities.",
                        description="The application appears to use SHA1 for hashing. SHA1 has known collision vulnerabilities and should be avoided for security-sensitive operations.",
                        remediation="Replace SHA1 with SHA-256 or SHA-3 for general hashing, or bcrypt/scrypt/Argon2 for passwords.",
                        confidence=0.70,
                        detector_name=self.name,
                    ))
                    break

        except Exception:
            pass

        return vulnerabilities

    async def _check_cookie_security(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for insecure cookie configurations."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else [response.headers.get("set-cookie", "")]

            for cookie in cookies:
                if not cookie:
                    continue

                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0] if "=" in cookie else "unknown"

                # Check for session cookies without HttpOnly
                is_session_cookie = any(s in cookie_name.lower() for s in ["session", "sid", "token", "auth", "jwt"])
                
                if is_session_cookie:
                    if "httponly" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Session Cookie Missing HttpOnly",
                            severity=SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=cookie_name,
                            evidence=f"Session cookie '{cookie_name}' is set without HttpOnly flag.",
                            description="A session cookie is accessible to JavaScript. This increases the risk of session hijacking via XSS attacks.",
                            remediation="Add the HttpOnly flag to all session cookies to prevent JavaScript access.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

                    if "samesite" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Session Cookie Missing SameSite",
                            severity=SeverityLevel.LOW,
                            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=cookie_name,
                            evidence=f"Session cookie '{cookie_name}' is set without SameSite attribute.",
                            description="A session cookie lacks the SameSite attribute, making it vulnerable to CSRF attacks in older browsers.",
                            remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to session cookies.",
                            confidence=0.85,
                            detector_name=self.name,
                        ))

        except Exception:
            pass

        return vulnerabilities

    async def _check_mixed_content(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for mixed content (HTTP resources on HTTPS page)."""
        parsed = urlparse(endpoint.url)
        if parsed.scheme != "https":
            return None

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Look for HTTP resources in HTTPS page
            mixed_content_patterns = [
                r'src=["\']http://',
                r'href=["\']http://',
                r'action=["\']http://',
                r'url\(["\']?http://',
            ]

            for pattern in mixed_content_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return Vulnerability(
                        id=str(uuid4()),
                        name="Mixed Content",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="HTTPS page loads resources over HTTP. This weakens the security of the encrypted connection.",
                        description="The secure HTTPS page includes resources loaded over unencrypted HTTP. This can allow attackers to inject malicious content or steal data.",
                        remediation="Ensure all resources are loaded over HTTPS. Use protocol-relative URLs or update to HTTPS. Add 'upgrade-insecure-requests' CSP directive.",
                        confidence=0.90,
                        detector_name=self.name,
                    )

        except Exception:
            pass

        return None
