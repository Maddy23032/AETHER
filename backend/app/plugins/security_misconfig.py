"""Security Misconfiguration detection plugin - Enhanced version."""

import re
from typing import List, Optional, Dict, Any
from uuid import uuid4
from urllib.parse import urljoin
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": SeverityLevel.MEDIUM,
        "description": "HSTS header missing - site vulnerable to SSL stripping attacks",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    },
    "Content-Security-Policy": {
        "severity": SeverityLevel.MEDIUM,
        "description": "CSP header missing - no protection against XSS and data injection",
        "remediation": "Implement Content-Security-Policy with appropriate directives",
    },
    "X-Content-Type-Options": {
        "severity": SeverityLevel.LOW,
        "description": "X-Content-Type-Options missing - vulnerable to MIME sniffing",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header",
    },
    "X-Frame-Options": {
        "severity": SeverityLevel.MEDIUM,
        "description": "X-Frame-Options missing - vulnerable to clickjacking",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
    },
    "X-XSS-Protection": {
        "severity": SeverityLevel.LOW,
        "description": "X-XSS-Protection missing (legacy browsers may be vulnerable)",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' for legacy browser support",
    },
    "Referrer-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Referrer-Policy missing - referrer may leak sensitive URL data",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Permissions-Policy missing - browser features not restricted",
        "remediation": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
}

# Dangerous headers that should NOT be present
DANGEROUS_HEADERS = {
    "Server": {
        "pattern": r"(apache|nginx|iis|tomcat|jetty|express)/[\d\.]+",
        "severity": SeverityLevel.LOW,
        "description": "Server version disclosed - aids attacker reconnaissance",
    },
    "X-Powered-By": {
        "pattern": r".+",
        "severity": SeverityLevel.LOW,
        "description": "Technology stack disclosed via X-Powered-By header",
    },
    "X-AspNet-Version": {
        "pattern": r".+",
        "severity": SeverityLevel.LOW,
        "description": "ASP.NET version disclosed",
    },
    "X-AspNetMvc-Version": {
        "pattern": r".+",
        "severity": SeverityLevel.LOW,
        "description": "ASP.NET MVC version disclosed",
    },
}

# Sensitive paths to check
SENSITIVE_PATHS = [
    ("/.git/config", "Git repository exposed", SeverityLevel.CRITICAL),
    ("/.git/HEAD", "Git repository exposed", SeverityLevel.CRITICAL),
    ("/.svn/entries", "SVN repository exposed", SeverityLevel.CRITICAL),
    ("/.env", "Environment file exposed", SeverityLevel.CRITICAL),
    ("/config.php", "Config file exposed", SeverityLevel.CRITICAL),
    ("/wp-config.php", "WordPress config exposed", SeverityLevel.CRITICAL),
    ("/phpinfo.php", "PHP info page exposed", SeverityLevel.HIGH),
    ("/server-status", "Apache status page exposed", SeverityLevel.MEDIUM),
    ("/nginx_status", "Nginx status page exposed", SeverityLevel.MEDIUM),
    ("/.htaccess", "Apache config exposed", SeverityLevel.HIGH),
    ("/.htpasswd", "Apache password file exposed", SeverityLevel.CRITICAL),
    ("/web.config", "IIS config exposed", SeverityLevel.HIGH),
    ("/crossdomain.xml", "Flash crossdomain policy", SeverityLevel.LOW),
    ("/clientaccesspolicy.xml", "Silverlight access policy", SeverityLevel.LOW),
    ("/robots.txt", "Robots file (info disclosure)", SeverityLevel.INFO),
    ("/sitemap.xml", "Sitemap (info disclosure)", SeverityLevel.INFO),
    ("/.DS_Store", "macOS directory file exposed", SeverityLevel.MEDIUM),
    ("/backup.sql", "Database backup exposed", SeverityLevel.CRITICAL),
    ("/dump.sql", "Database dump exposed", SeverityLevel.CRITICAL),
    ("/debug", "Debug endpoint exposed", SeverityLevel.HIGH),
    ("/trace", "Trace endpoint exposed", SeverityLevel.HIGH),
    ("/actuator", "Spring actuator exposed", SeverityLevel.HIGH),
    ("/actuator/health", "Spring health endpoint", SeverityLevel.MEDIUM),
    ("/actuator/env", "Spring environment endpoint", SeverityLevel.CRITICAL),
    ("/swagger-ui.html", "Swagger UI exposed", SeverityLevel.MEDIUM),
    ("/api-docs", "API documentation exposed", SeverityLevel.LOW),
    ("/graphql", "GraphQL endpoint (check introspection)", SeverityLevel.LOW),
    ("/admin", "Admin panel", SeverityLevel.MEDIUM),
    ("/administrator", "Admin panel", SeverityLevel.MEDIUM),
    ("/phpmyadmin", "phpMyAdmin exposed", SeverityLevel.HIGH),
    ("/elmah.axd", "ELMAH error log exposed", SeverityLevel.HIGH),
]

# Cookie security checks
COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


class SecurityMisconfigDetector(BaseDetector):
    """Enhanced Security Misconfiguration detector."""

    name = "Security Misconfiguration Detector"
    description = "Detects missing security headers, exposed files, and configuration issues"

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            response = await http_client.get(endpoint.url)
            
            # Check security headers
            header_vulns = self._check_security_headers(endpoint.url, response.headers)
            vulnerabilities.extend(header_vulns)
            
            # Check for dangerous headers
            dangerous_vulns = self._check_dangerous_headers(endpoint.url, response.headers)
            vulnerabilities.extend(dangerous_vulns)
            
            # Check cookie security
            cookie_vulns = self._check_cookie_security(endpoint.url, response.headers)
            vulnerabilities.extend(cookie_vulns)
            
            # Check for CORS misconfiguration
            cors_vuln = await self._check_cors(endpoint, http_client)
            if cors_vuln:
                vulnerabilities.append(cors_vuln)
            
        except Exception:
            pass
        
        # Check sensitive paths (only for root/main endpoints)
        if endpoint.url.count('/') <= 3:  # Near root
            path_vulns = await self._check_sensitive_paths(endpoint, http_client)
            vulnerabilities.extend(path_vulns)
        
        return vulnerabilities

    def _check_security_headers(
        self, 
        url: str, 
        headers: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Check for missing security headers."""
        vulnerabilities = []
        header_keys_lower = {k.lower(): k for k in headers.keys()}
        
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in header_keys_lower:
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    endpoint=url,
                    method="GET",
                    parameter=None,
                    evidence=f"Header '{header}' not present in response",
                    description=info["description"],
                    remediation=info["remediation"],
                    confidence=1.0,
                    detector_name=self.name,
                ))
        
        return vulnerabilities

    def _check_dangerous_headers(
        self, 
        url: str, 
        headers: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Check for headers that reveal sensitive information."""
        vulnerabilities = []
        
        for header, info in DANGEROUS_HEADERS.items():
            header_value = headers.get(header, "")
            if header_value and re.search(info["pattern"], header_value, re.I):
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name=f"Information Disclosure: {header}",
                    severity=info["severity"],
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    endpoint=url,
                    method="GET",
                    parameter=None,
                    evidence=f"{header}: {header_value}",
                    description=info["description"],
                    remediation=f"Configure server to remove or obscure the {header} header",
                    confidence=1.0,
                    detector_name=self.name,
                ))
        
        return vulnerabilities

    def _check_cookie_security(
        self, 
        url: str, 
        headers: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Check for insecure cookie configurations."""
        vulnerabilities = []
        set_cookie = headers.get("Set-Cookie", "")
        
        if not set_cookie:
            return vulnerabilities
        
        # Check for missing flags
        cookie_lower = set_cookie.lower()
        
        if "secure" not in cookie_lower and url.startswith("https"):
            vulnerabilities.append(Vulnerability(
                id=str(uuid4()),
                name="Cookie Missing Secure Flag",
                severity=SeverityLevel.MEDIUM,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                endpoint=url,
                method="GET",
                parameter=None,
                evidence=f"Set-Cookie header missing Secure flag",
                description="Cookies without Secure flag can be transmitted over unencrypted connections",
                remediation="Add Secure flag to all cookies on HTTPS sites",
                confidence=0.95,
                detector_name=self.name,
            ))
        
        if "httponly" not in cookie_lower:
            vulnerabilities.append(Vulnerability(
                id=str(uuid4()),
                name="Cookie Missing HttpOnly Flag",
                severity=SeverityLevel.MEDIUM,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                endpoint=url,
                method="GET",
                parameter=None,
                evidence=f"Set-Cookie header missing HttpOnly flag",
                description="Cookies without HttpOnly flag can be accessed by JavaScript (XSS risk)",
                remediation="Add HttpOnly flag to session cookies",
                confidence=0.95,
                detector_name=self.name,
            ))
        
        if "samesite" not in cookie_lower:
            vulnerabilities.append(Vulnerability(
                id=str(uuid4()),
                name="Cookie Missing SameSite Flag",
                severity=SeverityLevel.LOW,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                endpoint=url,
                method="GET",
                parameter=None,
                evidence=f"Set-Cookie header missing SameSite attribute",
                description="Cookies without SameSite may be vulnerable to CSRF attacks",
                remediation="Add SameSite=Lax or SameSite=Strict to cookies",
                confidence=0.90,
                detector_name=self.name,
            ))
        
        return vulnerabilities

    async def _check_cors(
        self, 
        endpoint: DiscoveredEndpoint, 
        http_client: HttpClient
    ) -> Optional[Vulnerability]:
        """Check for CORS misconfiguration."""
        try:
            # Test with arbitrary origin
            response = await http_client.request(
                "OPTIONS",
                endpoint.url,
                headers={"Origin": "https://evil.com"}
            )
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            # Critical: Reflects arbitrary origin with credentials
            if acao == "https://evil.com" and acac.lower() == "true":
                return Vulnerability(
                    id=str(uuid4()),
                    name="CORS Misconfiguration - Origin Reflection with Credentials",
                    severity=SeverityLevel.CRITICAL,
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    endpoint=endpoint.url,
                    method="OPTIONS",
                    parameter=None,
                    evidence=f"ACAO reflects origin 'evil.com' with credentials allowed",
                    description="The server reflects arbitrary origins and allows credentials, enabling cross-origin attacks",
                    remediation="Whitelist specific trusted origins. Never reflect arbitrary origins with credentials.",
                    confidence=0.95,
                    detector_name=self.name,
                )
            
            # High: Wildcard with credentials (invalid but sometimes misconfigured)
            if acao == "*":
                return Vulnerability(
                    id=str(uuid4()),
                    name="CORS Wildcard Origin",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    endpoint=endpoint.url,
                    method="OPTIONS",
                    parameter=None,
                    evidence=f"ACAO set to wildcard (*)",
                    description="The server allows any origin to access resources",
                    remediation="Restrict CORS to specific trusted origins",
                    confidence=0.85,
                    detector_name=self.name,
                )
                
        except Exception:
            pass
        
        return None

    async def _check_sensitive_paths(
        self, 
        endpoint: DiscoveredEndpoint, 
        http_client: HttpClient
    ) -> List[Vulnerability]:
        """Check for exposed sensitive files and paths."""
        vulnerabilities = []
        base_url = endpoint.url.rstrip('/')
        
        # Extract base domain
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path, description, severity in SENSITIVE_PATHS[:15]:  # Limit checks
            try:
                full_url = urljoin(base_url, path)
                response = await http_client.get(full_url)
                
                # Check for successful response with content
                if response.status_code == 200 and len(response.text) > 0:
                    # Verify it's not a generic 404 page
                    if not self._is_soft_404(response.text, path):
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Sensitive Path Exposed: {path}",
                            severity=severity,
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                            endpoint=full_url,
                            method="GET",
                            parameter=None,
                            evidence=f"Path {path} returned {response.status_code} with {len(response.text)} bytes",
                            description=description,
                            remediation=f"Restrict access to {path} or remove from production",
                            confidence=0.80,
                            detector_name=self.name,
                        ))
            except Exception:
                continue
        
        return vulnerabilities

    def _is_soft_404(self, content: str, path: str) -> bool:
        """Check if response is a soft 404 (custom error page returning 200)."""
        lower_content = content.lower()
        soft_404_indicators = [
            "not found", "404", "page doesn't exist", "page does not exist",
            "couldn't find", "could not find", "no page", "error",
        ]
        return any(ind in lower_content for ind in soft_404_indicators)
