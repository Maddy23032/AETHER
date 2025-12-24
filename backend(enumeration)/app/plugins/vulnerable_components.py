"""Vulnerable and Outdated Components detection plugin - OWASP A06:2021."""

import re
from typing import List, Optional, Dict, Tuple
from uuid import uuid4
from urllib.parse import urljoin, urlparse
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Known vulnerable library versions and their CVEs
VULNERABLE_LIBRARIES: Dict[str, List[Tuple[str, str, str, str]]] = {
    # (version_pattern, max_safe_version, severity, CVE/description)
    "jquery": [
        (r"jquery[/-]?(1\.[0-9]|2\.[0-2]|3\.0)", "3.5.0", "high", "CVE-2020-11022/CVE-2020-11023 XSS"),
        (r"jquery[/-]?1\.[0-7]\.", "1.8.0", "high", "Multiple XSS vulnerabilities"),
        (r"jquery[/-]?1\.(8|9|10|11)\.", "1.12.0", "medium", "CVE-2015-9251 XSS"),
    ],
    "angular": [
        (r"angular[/-]?1\.[0-5]\.", "1.6.0", "high", "Multiple XSS and sandbox escape"),
        (r"angularjs[/-]?1\.[0-6]\.", "1.7.0", "medium", "Template injection"),
    ],
    "bootstrap": [
        (r"bootstrap[/-]?(3\.[0-3]|4\.[0-3])", "4.3.1", "medium", "CVE-2019-8331 XSS"),
        (r"bootstrap[/-]?[23]\.[0-2]", "3.4.0", "medium", "CVE-2018-14041 XSS"),
    ],
    "vue": [
        (r"vue[/-]?2\.[0-5]\.", "2.6.0", "medium", "Template injection vulnerabilities"),
    ],
    "react": [
        (r"react[/-]?0\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13)\.", "0.14.0", "medium", "XSS vulnerabilities"),
    ],
    "lodash": [
        (r"lodash[/-]?[1-3]\.", "4.17.12", "high", "CVE-2019-10744 Prototype Pollution"),
        (r"lodash[/-]?4\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)\.", "4.17.21", "high", "CVE-2020-8203 Prototype Pollution"),
    ],
    "moment": [
        (r"moment[/-]?2\.[0-9]\.", "2.29.4", "medium", "CVE-2022-24785 Path Traversal"),
    ],
    "axios": [
        (r"axios[/-]?0\.(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\.", "0.21.1", "medium", "CVE-2020-28168 SSRF"),
    ],
    "handlebars": [
        (r"handlebars[/-]?(1|2|3|4\.[0-5])\.", "4.6.0", "critical", "CVE-2019-19919 Prototype Pollution RCE"),
    ],
    "dompurify": [
        (r"dompurify[/-]?(0|1)\.", "2.0.0", "high", "Multiple XSS bypass vulnerabilities"),
    ],
}

# Server software version patterns
SERVER_SIGNATURES: Dict[str, List[Tuple[str, str, str, str]]] = {
    "apache": [
        (r"Apache/(2\.2\.[0-9]|2\.4\.[0-9]|2\.4\.[0-3][0-9])", "2.4.50", "high", "Multiple CVEs including path traversal"),
        (r"Apache/1\.", "2.0.0", "critical", "End of life, multiple vulnerabilities"),
    ],
    "nginx": [
        (r"nginx/(0\.|1\.[0-9]\.|1\.1[0-7]\.)", "1.20.0", "medium", "Multiple security issues"),
    ],
    "iis": [
        (r"IIS/(6|7|8)\.", "10.0", "high", "End of life or multiple CVEs"),
    ],
    "php": [
        (r"PHP/(5\.|7\.[0-3]\.)", "7.4.0", "high", "Multiple security vulnerabilities"),
        (r"PHP/7\.4\.[0-9]$|PHP/7\.4\.[0-2][0-9]$", "7.4.30", "medium", "Security updates available"),
    ],
    "openssl": [
        (r"OpenSSL/(0\.|1\.0\.)", "1.1.1", "critical", "Heartbleed, multiple CVEs"),
    ],
    "tomcat": [
        (r"Tomcat/(7\.|8\.[0-4]|9\.[0-3])", "9.0.50", "high", "Multiple RCE and information disclosure"),
    ],
}

# CMS and framework patterns
CMS_PATTERNS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "wordpress": [
        (r"WordPress\s*([\d.]+)", "6.0", "medium", "Check for updates"),
        (r"wp-includes/version\.php.*\$wp_version\s*=\s*'([^']+)'", "6.0", "medium", "WordPress version disclosure"),
    ],
    "drupal": [
        (r"Drupal\s*([\d.]+)", "9.0", "high", "Check for Drupalgeddon patches"),
        (r"drupal.*version.*([7-8]\.[0-9]+)", "9.0", "high", "Potential SA-CORE vulnerabilities"),
    ],
    "joomla": [
        (r"Joomla!\s*([\d.]+)", "4.0", "medium", "Check for updates"),
    ],
}

# Known vulnerable paths and files
VULNERABLE_PATHS = [
    ("/cgi-bin/", "CGI scripts exposed - potential security risk"),
    ("/server-status", "Apache server-status exposed"),
    ("/server-info", "Apache server-info exposed"),
    ("/.git/config", "Git repository exposed"),
    ("/.svn/entries", "SVN repository exposed"),
    ("/.env", "Environment file exposed"),
    ("/config.php.bak", "Backup configuration file"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/web.config", "IIS configuration exposed"),
    ("/phpinfo.php", "PHP info exposed"),
    ("/adminer.php", "Adminer database tool exposed"),
    ("/phpmyadmin/", "phpMyAdmin exposed"),
    ("/elmah.axd", "ELMAH error log exposed"),
]


class VulnerableComponentsDetector(BaseDetector):
    """Detects Vulnerable and Outdated Components (OWASP A06:2021)."""

    name = "Vulnerable Components Detector"
    description = "Detects outdated libraries, frameworks, and server software with known vulnerabilities"

    def __init__(self):
        self.checked_hosts: set = set()
        self.detected_components: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Detect JavaScript libraries in response
        lib_vulns = await self._detect_js_libraries(endpoint, http_client)
        vulnerabilities.extend(lib_vulns)

        # Check server headers
        server_vulns = await self._check_server_headers(endpoint, http_client)
        vulnerabilities.extend(server_vulns)

        # Check for CMS/framework versions
        cms_vulns = await self._detect_cms(endpoint, http_client)
        vulnerabilities.extend(cms_vulns)

        # Check for vulnerable paths (once per host)
        path_vulns = await self._check_vulnerable_paths(endpoint, http_client)
        vulnerabilities.extend(path_vulns)

        # Check for outdated TLS
        tls_vulns = await self._check_tls_version(endpoint, http_client)
        vulnerabilities.extend(tls_vulns)

        return vulnerabilities

    async def _detect_js_libraries(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Detect vulnerable JavaScript libraries."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Look for library references in HTML and inline JS
            for library, versions in VULNERABLE_LIBRARIES.items():
                # Skip if already detected for this endpoint
                component_key = f"{endpoint.url}:{library}"
                if component_key in self.detected_components:
                    continue

                for version_pattern, safe_version, severity, cve_info in versions:
                    # Search for version in script tags, CDN URLs, or inline references
                    patterns = [
                        rf'{library}[.-]?(?:min\.)?js\?v?=?{version_pattern}',
                        rf'{library}@{version_pattern}',
                        rf'/{library}/{version_pattern}',
                        rf'{library}\.version\s*=\s*["\']?{version_pattern}',
                        rf'cdnjs\.cloudflare\.com/ajax/libs/{library}/{version_pattern}',
                        rf'cdn\.jsdelivr\.net/npm/{library}@{version_pattern}',
                        rf'unpkg\.com/{library}@{version_pattern}',
                    ]

                    for pattern in patterns:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            self.detected_components.add(component_key)
                            
                            severity_level = {
                                "critical": SeverityLevel.CRITICAL,
                                "high": SeverityLevel.HIGH,
                                "medium": SeverityLevel.MEDIUM,
                                "low": SeverityLevel.LOW,
                            }.get(severity, SeverityLevel.MEDIUM)

                            vulnerabilities.append(Vulnerability(
                                id=str(uuid4()),
                                name=f"Vulnerable {library.title()} Library",
                                severity=severity_level,
                                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                                endpoint=endpoint.url,
                                method="GET",
                                parameter=None,
                                evidence=f"Detected {library} version matching '{version_pattern}'. Safe version: {safe_version}. Issue: {cve_info}",
                                description=f"The page uses a vulnerable version of {library}. This version is affected by known security vulnerabilities that could be exploited by attackers.",
                                remediation=f"Update {library} to version {safe_version} or later. Review the security advisory for {cve_info}.",
                                confidence=0.90,
                                detector_name=self.name,
                            ))
                            break
                    else:
                        continue
                    break  # Found vulnerable version, stop checking this library

        except Exception:
            pass

        return vulnerabilities

    async def _check_server_headers(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check server response headers for vulnerable software."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            headers = response.headers

            # Check Server header
            server_header = headers.get("server", "") or headers.get("Server", "")
            x_powered_by = headers.get("x-powered-by", "") or headers.get("X-Powered-By", "")

            for software, versions in SERVER_SIGNATURES.items():
                for version_pattern, safe_version, severity, cve_info in versions:
                    # Check in server header
                    match = re.search(version_pattern, server_header, re.IGNORECASE)
                    if match:
                        component_key = f"{urlparse(endpoint.url).netloc}:{software}"
                        if component_key not in self.detected_components:
                            self.detected_components.add(component_key)
                            
                            severity_level = {
                                "critical": SeverityLevel.CRITICAL,
                                "high": SeverityLevel.HIGH,
                                "medium": SeverityLevel.MEDIUM,
                            }.get(severity, SeverityLevel.MEDIUM)

                            vulnerabilities.append(Vulnerability(
                                id=str(uuid4()),
                                name=f"Outdated {software.title()} Server",
                                severity=severity_level,
                                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                                endpoint=endpoint.url,
                                method="GET",
                                parameter=None,
                                evidence=f"Server header reveals: '{server_header}'. Vulnerable pattern detected. Issue: {cve_info}",
                                description=f"The server is running an outdated version of {software} with known security vulnerabilities.",
                                remediation=f"Update {software} to version {safe_version} or later. Consider hiding version information in production.",
                                confidence=0.95,
                                detector_name=self.name,
                            ))
                        break

                    # Check in X-Powered-By
                    match = re.search(version_pattern, x_powered_by, re.IGNORECASE)
                    if match:
                        component_key = f"{urlparse(endpoint.url).netloc}:{software}"
                        if component_key not in self.detected_components:
                            self.detected_components.add(component_key)

                            severity_level = {
                                "critical": SeverityLevel.CRITICAL,
                                "high": SeverityLevel.HIGH,
                                "medium": SeverityLevel.MEDIUM,
                            }.get(severity, SeverityLevel.MEDIUM)

                            vulnerabilities.append(Vulnerability(
                                id=str(uuid4()),
                                name=f"Outdated {software.upper()} Version",
                                severity=severity_level,
                                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                                endpoint=endpoint.url,
                                method="GET",
                                parameter=None,
                                evidence=f"X-Powered-By header reveals: '{x_powered_by}'. Issue: {cve_info}",
                                description=f"The server discloses that it's running an outdated version of {software}.",
                                remediation=f"Update {software} to version {safe_version} or later. Remove or hide the X-Powered-By header.",
                                confidence=0.95,
                                detector_name=self.name,
                            ))
                        break

            # Version disclosure warning (even if not vulnerable)
            if server_header and re.search(r'/[\d.]+', server_header):
                component_key = f"{urlparse(endpoint.url).netloc}:version_disclosure"
                if component_key not in self.detected_components:
                    self.detected_components.add(component_key)
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Server Version Disclosure",
                        severity=SeverityLevel.LOW,
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"Server header exposes version information: '{server_header}'",
                        description="The server discloses its version in response headers. This information helps attackers identify known vulnerabilities.",
                        remediation="Configure the server to hide version information. Use ServerTokens Prod (Apache) or server_tokens off (nginx).",
                        confidence=0.95,
                        detector_name=self.name,
                    ))

        except Exception:
            pass

        return vulnerabilities

    async def _detect_cms(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Detect CMS and framework versions."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # WordPress detection
            wp_patterns = [
                (r'<meta name="generator" content="WordPress ([\d.]+)"', "WordPress"),
                (r'/wp-content/', "WordPress"),
                (r'/wp-includes/', "WordPress"),
            ]

            for pattern, cms in wp_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    component_key = f"{urlparse(endpoint.url).netloc}:{cms}"
                    if component_key not in self.detected_components:
                        self.detected_components.add(component_key)
                        
                        version = match.group(1) if match.lastindex else "unknown"
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"{cms} Detected",
                            severity=SeverityLevel.INFO,
                            owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence=f"{cms} installation detected. Version: {version}",
                            description=f"The site runs {cms}. Ensure it's updated to the latest version and security plugins are installed.",
                            remediation=f"Keep {cms} and all plugins updated. Use security plugins. Enable auto-updates if possible.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))
                    break

            # Drupal detection
            if re.search(r'Drupal|/sites/default/|drupal\.js', text, re.IGNORECASE):
                component_key = f"{urlparse(endpoint.url).netloc}:Drupal"
                if component_key not in self.detected_components:
                    self.detected_components.add(component_key)
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Drupal CMS Detected",
                        severity=SeverityLevel.INFO,
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="Drupal CMS installation detected.",
                        description="The site runs Drupal. Ensure security patches (especially Drupalgeddon) are applied.",
                        remediation="Keep Drupal core and modules updated. Apply all security advisories (SA-CORE).",
                        confidence=0.85,
                        detector_name=self.name,
                    ))

        except Exception:
            pass

        return vulnerabilities

    async def _check_vulnerable_paths(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for exposed vulnerable paths and files."""
        vulnerabilities = []
        
        parsed = urlparse(endpoint.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Only check once per host
        if base_url in self.checked_hosts:
            return []
        self.checked_hosts.add(base_url)

        for path, description in VULNERABLE_PATHS[:15]:  # Limit checks
            try:
                test_url = urljoin(base_url, path)
                response = await http_client.get(test_url)

                if response.status_code == 200:
                    # Verify it's not a custom 404
                    if len(response.text) > 50:  # Has content
                        severity = SeverityLevel.HIGH if any(s in path for s in [".git", ".env", "config", "phpmyadmin"]) else SeverityLevel.MEDIUM
                        
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Sensitive Path Exposed: {path}",
                            severity=severity,
                            owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                            endpoint=test_url,
                            method="GET",
                            parameter=None,
                            evidence=f"{description}. Path {path} returns HTTP 200 with {len(response.text)} bytes of content.",
                            description=f"A sensitive path or file is publicly accessible. This could expose configuration, source code, or administrative interfaces.",
                            remediation="Restrict access to sensitive paths using server configuration. Remove or relocate sensitive files.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

            except Exception:
                continue

        return vulnerabilities

    async def _check_tls_version(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for outdated TLS versions (informational)."""
        vulnerabilities = []
        
        # This is a simplified check - full TLS testing requires SSL libraries
        parsed = urlparse(endpoint.url)
        if parsed.scheme != "https":
            return []

        # Check for TLS version headers if available
        try:
            response = await http_client.get(endpoint.url)
            
            # Some proxies/CDNs include TLS version in headers
            via = response.headers.get("via", "")
            if "TLS 1.0" in via or "SSL" in via:
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name="Outdated TLS Version",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"TLS 1.0 or SSL detected in Via header: {via}",
                    description="The server supports outdated TLS versions with known vulnerabilities (BEAST, POODLE).",
                    remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2 or 1.3 only. Configure secure cipher suites.",
                    confidence=0.80,
                    detector_name=self.name,
                ))

        except Exception:
            pass

        return vulnerabilities
