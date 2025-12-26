"""Broken Access Control detection plugin - OWASP A01:2021."""

import re
from typing import List, Optional, Set
from uuid import uuid4
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Common admin/privileged paths to test for unauthorized access
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/dashboard",
    "/admin/login", "/admin/panel", "/admincp", "/admin.php",
    "/wp-admin", "/wp-admin/", "/backend", "/manage", "/manager",
    "/control", "/controlpanel", "/cpanel", "/dashboard",
    "/console", "/system", "/sysadmin", "/root", "/superuser",
    "/moderator", "/webmaster", "/master", "/config", "/configuration",
    "/setup", "/install", "/maintenance", "/debug", "/test",
    "/api/admin", "/api/v1/admin", "/api/internal", "/api/private",
    "/internal", "/private", "/restricted", "/secure", "/hidden",
    "/backup", "/backups", "/db", "/database", "/logs", "/log",
    "/tmp", "/temp", "/cache", "/upload", "/uploads", "/files",
    "/.git", "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/elmah.axd", "/trace.axd", "/web.config", "/crossdomain.xml",
]

# Common IDOR parameter patterns
IDOR_PARAMS = [
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "profile_id", "profileid", "customer_id", "customerid",
    "order_id", "orderid", "invoice_id", "invoiceid",
    "doc_id", "docid", "document_id", "file_id", "fileid",
    "record_id", "recordid", "item_id", "itemid", "product_id",
    "ref", "reference", "no", "num", "number", "key", "token",
    "session", "sess_id", "sessid", "user", "account", "member",
]

# Patterns indicating access control issues
ACCESS_CONTROL_INDICATORS = {
    "admin_access": [
        r"admin.*panel", r"dashboard", r"control\s*panel",
        r"administration", r"management\s*console", r"admin\s*area",
        r"logged\s*in\s*as\s*admin", r"administrator\s*dashboard",
        r"user\s*management", r"system\s*settings", r"configuration",
    ],
    "sensitive_data": [
        r"password", r"passwd", r"pwd", r"secret", r"api[_-]?key",
        r"private[_-]?key", r"token", r"auth", r"credential",
        r"ssn", r"social\s*security", r"credit\s*card", r"cc_number",
        r"bank\s*account", r"routing\s*number",
    ],
    "debug_info": [
        r"debug\s*mode", r"stack\s*trace", r"exception", r"error\s*log",
        r"phpinfo", r"server\s*info", r"environment\s*variables",
    ],
}

# HTTP methods to test for method override vulnerabilities
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class BrokenAccessControlDetector(BaseDetector):
    """Detects Broken Access Control vulnerabilities (OWASP A01:2021)."""

    name = "Broken Access Control Detector"
    description = "Detects IDOR, privilege escalation, forced browsing, and missing access controls"

    def __init__(self):
        self.tested_paths: Set[str] = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Test for IDOR in URL parameters
        for param in endpoint.parameters:
            if any(p in param.lower() for p in IDOR_PARAMS):
                vuln = await self._test_idor(endpoint, param, http_client)
                if vuln:
                    vulnerabilities.append(vuln)

        # Test for forced browsing / unauthorized admin access
        base_url = f"{urlparse(endpoint.url).scheme}://{urlparse(endpoint.url).netloc}"
        vuln = await self._test_forced_browsing(base_url, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Test for HTTP method tampering
        vuln = await self._test_method_tampering(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Test for horizontal privilege escalation in forms
        for form in endpoint.forms:
            vuln = await self._test_form_idor(endpoint, form, http_client)
            if vuln:
                vulnerabilities.append(vuln)

        # Test for path traversal in URL structure
        vuln = await self._test_path_manipulation(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_idor(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        try:
            # Get original response
            parsed = urlparse(endpoint.url)
            original_params = parse_qs(parsed.query)
            
            if param not in original_params:
                return None

            original_value = original_params[param][0]
            
            # Try numeric ID manipulation
            test_values = []
            if original_value.isdigit():
                original_int = int(original_value)
                test_values = [
                    str(original_int - 1),
                    str(original_int + 1),
                    "1",
                    "0",
                    str(original_int * 2),
                ]
            else:
                # For non-numeric IDs, try common manipulations
                test_values = [
                    "1", "0", "admin", "test", "user",
                    original_value + "1",
                    "../../../../etc/passwd",
                ]

            # Get baseline response
            baseline_resp = await http_client.get(endpoint.url)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code

            for test_value in test_values:
                try:
                    # Build test URL
                    test_params = original_params.copy()
                    test_params[param] = [test_value]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                    response = await http_client.get(test_url)

                    # Check for IDOR indicators
                    # 1. Different successful response (not 403/401)
                    if response.status_code == 200 and baseline_status == 200:
                        # Check if we got different data (potential IDOR)
                        length_diff = abs(len(response.text) - baseline_length)
                        if length_diff > 100:  # Significant content difference
                            # Check for sensitive data patterns
                            has_sensitive = any(
                                re.search(pattern, response.text, re.IGNORECASE)
                                for pattern in ACCESS_CONTROL_INDICATORS["sensitive_data"]
                            )
                            
                            if has_sensitive:
                                return Vulnerability(
                                    id=str(uuid4()),
                                    name="Insecure Direct Object Reference (IDOR)",
                                    severity=SeverityLevel.HIGH,
                                    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                                    endpoint=endpoint.url,
                                    method="GET",
                                    parameter=param,
                                    evidence=f"Manipulating '{param}' from '{original_value}' to '{test_value}' returned different data with sensitive content. Response length changed from {baseline_length} to {len(response.text)} bytes.",
                                    description=f"The parameter '{param}' appears to reference objects directly without proper authorization checks. An attacker could access or modify data belonging to other users.",
                                    remediation="Implement proper authorization checks. Verify the authenticated user has permission to access the requested resource. Use indirect references or UUIDs instead of sequential IDs.",
                                    confidence=0.85,
                                    detector_name=self.name,
                                )

                except Exception:
                    continue

        except Exception:
            pass
        return None

    async def _test_forced_browsing(
        self,
        base_url: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for unauthorized access to admin/sensitive paths."""
        # Only test once per base URL
        if base_url in self.tested_paths:
            return None
        self.tested_paths.add(base_url)

        accessible_paths = []

        for path in ADMIN_PATHS[:30]:  # Limit to avoid too many requests
            try:
                test_url = urljoin(base_url, path)
                response = await http_client.get(test_url)

                # Check if path is accessible (200 OK without redirect to login)
                if response.status_code == 200:
                    # Check for admin content indicators
                    has_admin_content = any(
                        re.search(pattern, response.text, re.IGNORECASE)
                        for pattern in ACCESS_CONTROL_INDICATORS["admin_access"]
                    )
                    
                    has_debug_content = any(
                        re.search(pattern, response.text, re.IGNORECASE)
                        for pattern in ACCESS_CONTROL_INDICATORS["debug_info"]
                    )

                    if has_admin_content or has_debug_content:
                        accessible_paths.append(path)
                        
                        # Return immediately for high-confidence findings
                        if has_admin_content:
                            return Vulnerability(
                                id=str(uuid4()),
                                name="Unauthorized Admin Panel Access",
                                severity=SeverityLevel.CRITICAL,
                                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                                endpoint=test_url,
                                method="GET",
                                parameter=None,
                                evidence=f"Admin panel accessible without authentication at {path}. Response contains administrative interface indicators.",
                                description="An administrative interface is accessible without proper authentication. This allows attackers to access privileged functionality and potentially compromise the entire application.",
                                remediation="Implement proper authentication and authorization for all administrative interfaces. Use role-based access control (RBAC). Consider IP whitelisting for admin panels.",
                                confidence=0.95,
                                detector_name=self.name,
                            )

            except Exception:
                continue

        # Report debug/sensitive paths as medium severity
        if accessible_paths:
            return Vulnerability(
                id=str(uuid4()),
                name="Sensitive Path Exposure",
                severity=SeverityLevel.MEDIUM,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                endpoint=base_url,
                method="GET",
                parameter=None,
                evidence=f"Accessible sensitive paths: {', '.join(accessible_paths[:5])}",
                description="Sensitive or administrative paths are accessible without proper authentication. These endpoints may expose debug information, configuration details, or administrative functionality.",
                remediation="Restrict access to sensitive paths using authentication. Disable debug endpoints in production. Use proper access control lists.",
                confidence=0.75,
                detector_name=self.name,
            )

        return None

    async def _test_method_tampering(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for HTTP method tampering vulnerabilities."""
        try:
            # Get baseline with GET
            baseline = await http_client.get(endpoint.url)
            
            if baseline.status_code == 403 or baseline.status_code == 401:
                # Try other methods to bypass
                for method in ["POST", "PUT", "PATCH", "DELETE"]:
                    try:
                        if method == "POST":
                            response = await http_client.post(endpoint.url)
                        elif method == "PUT":
                            response = await http_client.request("PUT", endpoint.url)
                        elif method == "PATCH":
                            response = await http_client.request("PATCH", endpoint.url)
                        elif method == "DELETE":
                            response = await http_client.request("DELETE", endpoint.url)
                        else:
                            continue

                        if response.status_code == 200:
                            return Vulnerability(
                                id=str(uuid4()),
                                name="HTTP Method Tampering Bypass",
                                severity=SeverityLevel.HIGH,
                                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                                endpoint=endpoint.url,
                                method=method,
                                parameter=None,
                                evidence=f"GET returned {baseline.status_code}, but {method} returned 200 OK. Access control can be bypassed using different HTTP methods.",
                                description="The access control mechanism only checks certain HTTP methods. By using a different method, an attacker can bypass security restrictions.",
                                remediation="Implement access control checks for all HTTP methods. Use a security framework that handles method-agnostic authorization.",
                                confidence=0.90,
                                detector_name=self.name,
                            )
                    except Exception:
                        continue

        except Exception:
            pass
        return None

    async def _test_form_idor(
        self,
        endpoint: DiscoveredEndpoint,
        form: dict,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for IDOR in form hidden fields."""
        try:
            hidden_inputs = [
                inp for inp in form.get("inputs", [])
                if inp.get("type") == "hidden"
            ]

            for inp in hidden_inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")

                if any(p in name.lower() for p in IDOR_PARAMS) and value:
                    # Test with manipulated value
                    test_value = "1" if not value.isdigit() else str(int(value) + 1)
                    
                    form_data = {
                        i.get("name"): i.get("value", "test")
                        for i in form.get("inputs", [])
                        if i.get("name")
                    }
                    form_data[name] = test_value

                    action = form.get("action") or endpoint.url
                    if not action.startswith("http"):
                        action = urljoin(endpoint.url, action)

                    response = await http_client.post(action, data=form_data)

                    # Check for success indicators (potential IDOR)
                    if response.status_code == 200 and len(response.text) > 100:
                        # Look for error messages that indicate the ID was processed
                        no_error_patterns = [
                            r"not\s*found", r"invalid", r"error",
                            r"unauthorized", r"forbidden", r"denied"
                        ]
                        has_error = any(
                            re.search(p, response.text, re.IGNORECASE)
                            for p in no_error_patterns
                        )
                        
                        if not has_error:
                            return Vulnerability(
                                id=str(uuid4()),
                                name="Hidden Field IDOR",
                                severity=SeverityLevel.HIGH,
                                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                                endpoint=action,
                                method="POST",
                                parameter=name,
                                evidence=f"Hidden field '{name}' with value '{value}' was modified to '{test_value}' and the request was processed successfully.",
                                description=f"The hidden field '{name}' can be manipulated to access or modify data belonging to other users. The server does not properly validate that the user has permission to access the referenced object.",
                                remediation="Never trust hidden form fields for authorization. Always validate on the server that the authenticated user has permission to access the referenced resource.",
                                confidence=0.80,
                                detector_name=self.name,
                            )

        except Exception:
            pass
        return None

    async def _test_path_manipulation(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for path-based access control bypass."""
        try:
            parsed = urlparse(endpoint.url)
            path = parsed.path

            # Look for paths with IDs that could be manipulated
            # e.g., /users/123/profile -> /users/124/profile
            id_pattern = re.search(r'/(\d+)/', path)
            if id_pattern:
                original_id = id_pattern.group(1)
                test_id = str(int(original_id) + 1)
                
                new_path = path.replace(f"/{original_id}/", f"/{test_id}/")
                test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                
                if parsed.query:
                    test_url += f"?{parsed.query}"

                baseline = await http_client.get(endpoint.url)
                response = await http_client.get(test_url)

                # Check if we can access other users' data
                if response.status_code == 200 and baseline.status_code == 200:
                    if len(response.text) > 100 and abs(len(response.text) - len(baseline.text)) > 50:
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Path-based IDOR",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            endpoint=test_url,
                            method="GET",
                            parameter="path",
                            evidence=f"Modifying path ID from '{original_id}' to '{test_id}' returned different content, suggesting access to another user's data.",
                            description="The application uses predictable resource paths without proper authorization. An attacker can enumerate and access resources belonging to other users by manipulating path parameters.",
                            remediation="Implement server-side authorization checks for all resource access. Verify the authenticated user owns or has permission to access the requested resource.",
                            confidence=0.85,
                            detector_name=self.name,
                        )

        except Exception:
            pass
        return None
