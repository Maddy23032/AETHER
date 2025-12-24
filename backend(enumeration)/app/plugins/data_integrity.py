"""Software and Data Integrity Failures detection plugin - OWASP A08:2021."""

import re
import hashlib
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urlparse, urljoin
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# CDN domains that should use SRI
CDN_DOMAINS = [
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "fonts.googleapis.com",
    "use.fontawesome.com",
    "cdn.tailwindcss.com",
    "cdn.datatables.net",
]

# Deserialization vulnerability patterns
DESERIALIZATION_PATTERNS = [
    # Java
    (r'ObjectInputStream', "Java deserialization"),
    (r'\.readObject\(\)', "Java deserialization"),
    (r'XMLDecoder', "Java XML deserialization"),
    # PHP
    (r'unserialize\s*\(', "PHP unserialize"),
    (r'__wakeup', "PHP magic method"),
    (r'__destruct', "PHP magic method"),
    # Python
    (r'pickle\.loads?', "Python pickle"),
    (r'yaml\.load\s*\([^,)]+\)', "Python YAML unsafe load"),
    (r'marshal\.loads?', "Python marshal"),
    # .NET
    (r'BinaryFormatter', ".NET binary deserialization"),
    (r'NetDataContractSerializer', ".NET deserialization"),
    (r'TypeNameHandling', ".NET JSON deserialization"),
    # Node.js
    (r'node-serialize', "Node.js serialize"),
    (r'serialize-javascript', "JavaScript serialization"),
]

# Update mechanism vulnerability indicators
UPDATE_PATTERNS = [
    (r'auto.?update', "Auto-update functionality"),
    (r'check.?update', "Update check"),
    (r'download.?update', "Update download"),
    (r'update.?url', "Update URL"),
    (r'update.?server', "Update server"),
]

# CI/CD exposure patterns
CICD_PATTERNS = [
    (r'\.travis\.yml', "Travis CI config"),
    (r'\.github/workflows', "GitHub Actions"),
    (r'Jenkinsfile', "Jenkins pipeline"),
    (r'\.gitlab-ci\.yml', "GitLab CI config"),
    (r'azure-pipelines\.yml', "Azure DevOps"),
    (r'\.circleci', "CircleCI config"),
    (r'bitbucket-pipelines\.yml', "Bitbucket Pipelines"),
]


class DataIntegrityDetector(BaseDetector):
    """Detects Software and Data Integrity Failures (OWASP A08:2021)."""

    name = "Data Integrity Failures Detector"
    description = "Detects insecure deserialization, missing SRI, unsigned updates, and CI/CD exposure"

    def __init__(self):
        self.checked_hosts: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Check for missing Subresource Integrity (SRI)
        sri_vulns = await self._check_missing_sri(endpoint, http_client)
        vulnerabilities.extend(sri_vulns)

        # Check for deserialization indicators
        deser_vulns = await self._check_deserialization(endpoint, http_client)
        vulnerabilities.extend(deser_vulns)

        # Check for insecure update mechanisms
        vuln = await self._check_update_mechanism(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for exposed CI/CD configurations
        cicd_vulns = await self._check_cicd_exposure(endpoint, http_client)
        vulnerabilities.extend(cicd_vulns)

        # Check for unsigned or unverified resources
        vuln = await self._check_unsigned_resources(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for client-side template injection
        vuln = await self._check_template_injection(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_missing_sri(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for external resources without Subresource Integrity."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Find script tags from CDNs
            script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
            link_pattern = r'<link[^>]+href=["\']([^"\']+)["\'][^>]*stylesheet[^>]*>'

            resources_without_sri = []

            for pattern in [script_pattern, link_pattern]:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for url in matches:
                    # Check if it's from a CDN
                    if any(cdn in url for cdn in CDN_DOMAINS):
                        # Check if the tag has integrity attribute
                        # Find the full tag
                        tag_pattern = rf'<(?:script|link)[^>]*(?:src|href)=["\']' + re.escape(url) + r'["\'][^>]*>'
                        tag_match = re.search(tag_pattern, text, re.IGNORECASE)
                        if tag_match:
                            tag = tag_match.group(0)
                            if 'integrity=' not in tag.lower():
                                resources_without_sri.append(url)

            if resources_without_sri:
                # Limit to first 5 for readability
                sample = resources_without_sri[:5]
                more = len(resources_without_sri) - 5 if len(resources_without_sri) > 5 else 0
                
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name="Missing Subresource Integrity (SRI)",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"CDN resources without SRI: {', '.join(sample)}{f' (+{more} more)' if more else ''}",
                    description="External scripts and stylesheets from CDNs lack Subresource Integrity hashes. If a CDN is compromised, malicious code could be injected without detection.",
                    remediation="Add integrity and crossorigin attributes to all external scripts and stylesheets. Use tools like srihash.org to generate hashes.",
                    confidence=0.95,
                    detector_name=self.name,
                ))

        except Exception:
            pass

        return vulnerabilities

    async def _check_deserialization(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for insecure deserialization indicators."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            for pattern, description in DESERIALIZATION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name=f"Potential Insecure Deserialization ({description})",
                        severity=SeverityLevel.HIGH,
                        owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"Pattern indicating {description} found in response.",
                        description=f"The application appears to use {description} which can lead to remote code execution if untrusted data is deserialized.",
                        remediation="Avoid deserializing untrusted data. Use safe serialization formats like JSON. Implement integrity checks on serialized data.",
                        confidence=0.70,
                        detector_name=self.name,
                    ))
                    break  # Report once per page

            # Check for serialized data in cookies
            cookies = response.headers.get("set-cookie", "")
            serialized_patterns = [
                (r'[a-zA-Z0-9+/=]{50,}', "Base64-encoded data"),
                (r'O:[0-9]+:"', "PHP serialized object"),
                (r'rO0AB', "Java serialized object (Base64)"),
            ]

            for pattern, description in serialized_patterns:
                if re.search(pattern, cookies):
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Serialized Data in Cookie",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"{description} detected in cookie. Attackers may be able to tamper with serialized data.",
                        description="The application stores serialized data in cookies. If this data is deserialized without validation, it may lead to tampering or code execution.",
                        remediation="Sign or encrypt cookies containing serialized data. Validate integrity before deserialization. Consider using JWTs with proper validation.",
                        confidence=0.75,
                        detector_name=self.name,
                    ))
                    break

        except Exception:
            pass

        return vulnerabilities

    async def _check_update_mechanism(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for insecure update mechanisms."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            for pattern, description in UPDATE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    # Check if update URL uses HTTP
                    http_update = re.search(r'http://[^"\'\s]+(?:update|download|upgrade)', text, re.IGNORECASE)
                    
                    if http_update:
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Insecure Update Mechanism",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence=f"{description} detected using HTTP: {http_update.group(0)[:80]}",
                            description="The application uses an insecure HTTP connection for software updates. Attackers could perform man-in-the-middle attacks to inject malicious updates.",
                            remediation="Use HTTPS for all update mechanisms. Implement cryptographic signature verification for updates.",
                            confidence=0.85,
                            detector_name=self.name,
                        )

        except Exception:
            pass

        return None

    async def _check_cicd_exposure(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for exposed CI/CD configuration files."""
        vulnerabilities = []
        
        parsed = urlparse(endpoint.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if base_url in self.checked_hosts:
            return []
        self.checked_hosts.add(base_url)

        cicd_paths = [
            "/.github/workflows/",
            "/.travis.yml",
            "/.gitlab-ci.yml",
            "/Jenkinsfile",
            "/.circleci/config.yml",
            "/azure-pipelines.yml",
            "/bitbucket-pipelines.yml",
            "/.drone.yml",
            "/appveyor.yml",
            "/Procfile",
        ]

        for path in cicd_paths:
            try:
                test_url = urljoin(base_url, path)
                response = await http_client.get(test_url)

                if response.status_code == 200 and len(response.text) > 20:
                    # Verify it's not a 404 page
                    if not re.search(r'404|not found|page doesn.?t exist', response.text, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Exposed CI/CD Configuration: {path}",
                            severity=SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                            endpoint=test_url,
                            method="GET",
                            parameter=None,
                            evidence=f"CI/CD configuration file accessible at {path}. May contain secrets, build process details, or deployment configurations.",
                            description="CI/CD configuration files are publicly accessible. These may expose secrets, internal infrastructure details, or provide information useful for supply chain attacks.",
                            remediation="Block access to CI/CD configuration files in production. Ensure secrets are stored in secure vaults, not configuration files.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

            except Exception:
                continue

        return vulnerabilities

    async def _check_unsigned_resources(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for resources loaded without verification."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Check for dynamic script loading without integrity
            dynamic_script_patterns = [
                r'document\.createElement\s*\(\s*["\']script["\']\s*\)',
                r'\.src\s*=\s*["\'][^"\']+["\']',
                r'new\s+Function\s*\(',
                r'eval\s*\(',
            ]

            for pattern in dynamic_script_patterns:
                match = re.search(pattern, text)
                if match:
                    # Check if there's any integrity verification nearby
                    context_start = max(0, match.start() - 200)
                    context_end = min(len(text), match.end() + 300)
                    context = text[context_start:context_end]
                    
                    if 'integrity' not in context.lower() and 'hash' not in context.lower():
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Dynamic Script Loading Without Verification",
                            severity=SeverityLevel.LOW,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence="Dynamic script creation detected without apparent integrity verification.",
                            description="The page dynamically loads scripts without verifying their integrity. If the source is compromised, malicious code could be executed.",
                            remediation="Implement integrity verification for dynamically loaded scripts. Use CSP with strict-dynamic where possible.",
                            confidence=0.65,
                            detector_name=self.name,
                        )

        except Exception:
            pass

        return None

    async def _check_template_injection(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for potential client-side template injection."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Template syntax patterns that might be vulnerable
            template_patterns = [
                (r'\{\{.*?\}\}', "Angular/Vue/Handlebars template syntax"),
                (r'\$\{.*?\}', "JavaScript template literal"),
                (r'<%.*?%>', "EJS/ASP template syntax"),
                (r'\[\[.*?\]\]', "Alternative template syntax"),
            ]

            # Check if user input might reach templates
            for param in endpoint.parameters:
                for pattern, description in template_patterns:
                    # Check if parameter value appears near template syntax
                    if re.search(rf'{param}.*{pattern}|{pattern}.*{param}', text, re.IGNORECASE):
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Potential Client-Side Template Injection",
                            severity=SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=f"Parameter '{param}' appears near {description}. User input may be evaluated in template context.",
                            description="User-controllable input appears to be used in client-side templates without proper sanitization. This could allow attackers to inject template expressions.",
                            remediation="Sanitize user input before template rendering. Use text binding instead of HTML binding. Implement CSP to mitigate impact.",
                            confidence=0.65,
                            detector_name=self.name,
                        )

        except Exception:
            pass

        return None
