"""Security Logging and Monitoring Failures detection plugin - OWASP A09:2021."""

import re
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urlparse, urljoin
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Error disclosure patterns that indicate poor logging practices
ERROR_DISCLOSURE_PATTERNS = [
    # Stack traces
    (r'at\s+[\w.$]+\([\w]+\.java:\d+\)', "Java stack trace", SeverityLevel.MEDIUM),
    (r'File\s+"[^"]+",\s+line\s+\d+', "Python stack trace", SeverityLevel.MEDIUM),
    (r'at\s+[\w.<>]+\s+in\s+[\w:\\/.]+:\d+', ".NET stack trace", SeverityLevel.MEDIUM),
    (r'#\d+\s+[\w\\/.]+\(\d+\):', "PHP stack trace", SeverityLevel.MEDIUM),
    (r'at\s+[\w.]+\s+\([\w/.]+:\d+:\d+\)', "Node.js stack trace", SeverityLevel.MEDIUM),
    
    # Database errors
    (r'ORA-\d{5}', "Oracle error code", SeverityLevel.MEDIUM),
    (r'MySQL.*Error', "MySQL error", SeverityLevel.MEDIUM),
    (r'PostgreSQL.*ERROR', "PostgreSQL error", SeverityLevel.MEDIUM),
    (r'SQLSTATE\[\w+\]', "SQL state error", SeverityLevel.MEDIUM),
    
    # Server configuration exposure
    (r'DocumentRoot', "Apache config exposure", SeverityLevel.LOW),
    (r'nginx/[\d.]+', "nginx version exposure", SeverityLevel.LOW),
    
    # Debug information
    (r'DEBUG\s*=\s*True', "Debug mode enabled", SeverityLevel.HIGH),
    (r'DEVELOPMENT\s*MODE', "Development mode enabled", SeverityLevel.HIGH),
]

# Headers indicating logging/monitoring
LOGGING_HEADERS = [
    "x-request-id",
    "x-correlation-id", 
    "x-trace-id",
    "traceparent",
    "x-amzn-requestid",
]

# Paths that might expose logs
LOG_PATHS = [
    "/logs",
    "/logs/",
    "/log",
    "/log/",
    "/debug",
    "/debug/",
    "/error_log",
    "/error.log",
    "/access.log",
    "/access_log",
    "/app.log",
    "/application.log",
    "/server.log",
    "/debug.log",
    "/trace.log",
    "/.log",
    "/var/log/",
    "/elmah.axd",
    "/trace.axd",
    "/errorlog.axd",
]

# Security-sensitive actions that should be logged
SECURITY_ACTIONS = [
    "login",
    "logout", 
    "password",
    "register",
    "signup",
    "admin",
    "delete",
    "payment",
    "checkout",
    "transfer",
    "api/auth",
]


class LoggingFailuresDetector(BaseDetector):
    """Detects Security Logging and Monitoring Failures (OWASP A09:2021)."""

    name = "Logging Failures Detector"
    description = "Detects verbose errors, exposed logs, missing security headers, and monitoring gaps"

    def __init__(self):
        self.checked_hosts: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Check for verbose error messages
        error_vulns = await self._check_error_disclosure(endpoint, http_client)
        vulnerabilities.extend(error_vulns)

        # Check for exposed log files
        log_vulns = await self._check_exposed_logs(endpoint, http_client)
        vulnerabilities.extend(log_vulns)

        # Check for missing security logging headers
        vuln = await self._check_logging_headers(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for debug endpoints
        debug_vulns = await self._check_debug_endpoints(endpoint, http_client)
        vulnerabilities.extend(debug_vulns)

        # Check for missing rate limiting (indicates no monitoring)
        vuln = await self._check_monitoring_indicators(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_error_disclosure(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for verbose error messages that expose internal details."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            for pattern, description, severity in ERROR_DISCLOSURE_PATTERNS:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    # Get some context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end].replace('\n', ' ').strip()
                    
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name=f"Verbose Error Disclosure: {description}",
                        severity=severity,
                        owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"Detected {description}: ...{context}...",
                        description="The application exposes detailed error information to users. This provides attackers with valuable information about the application's internals, libraries, and file structure.",
                        remediation="Implement custom error pages that don't expose technical details. Log detailed errors server-side only. Disable debug mode in production.",
                        confidence=0.90,
                        detector_name=self.name,
                    ))
                    break  # Report once per page

        except Exception:
            pass

        # Test error handling by triggering errors
        error_triggers = [
            ("param", "{{invalid}}", "template_error"),
            ("id", "-1", "invalid_id"),
            ("id", "9999999999999", "overflow"),
            ("page", "../../etc/passwd", "path_traversal"),
        ]

        for param, value, error_type in error_triggers:
            try:
                test_url = f"{endpoint.url}?{param}={value}"
                response = await http_client.get(test_url)
                
                for pattern, description, severity in ERROR_DISCLOSURE_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Error Disclosure via {error_type}",
                            severity=severity,
                            owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                            endpoint=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Triggering {error_type} with '{param}={value}' exposed {description}.",
                            description="Malformed input triggers verbose error messages. Attackers can probe the application to gather internal information.",
                            remediation="Implement proper input validation. Use generic error messages for clients. Log details server-side only.",
                            confidence=0.85,
                            detector_name=self.name,
                        ))
                        break
            except Exception:
                continue

        return vulnerabilities

    async def _check_exposed_logs(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for publicly accessible log files."""
        vulnerabilities = []
        
        parsed = urlparse(endpoint.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Only check once per host
        if base_url in self.checked_hosts:
            return []
        self.checked_hosts.add(base_url)

        for path in LOG_PATHS[:15]:  # Limit checks
            try:
                test_url = urljoin(base_url, path)
                response = await http_client.get(test_url)

                if response.status_code == 200:
                    text = response.text
                    
                    # Check for log file indicators
                    log_indicators = [
                        r'\[\d{4}-\d{2}-\d{2}',  # Date format
                        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
                        r'(INFO|DEBUG|WARN|ERROR|FATAL)\s*[\[:]',  # Log levels
                        r'GET\s+/|POST\s+/',  # HTTP methods
                        r'User-Agent:',  # Request headers
                    ]
                    
                    indicator_count = sum(1 for p in log_indicators if re.search(p, text))
                    
                    if indicator_count >= 2:  # At least 2 indicators
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Exposed Log File: {path}",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                            endpoint=test_url,
                            method="GET",
                            parameter=None,
                            evidence=f"Log file accessible at {path}. Contains {indicator_count} log format indicators (dates, IPs, log levels).",
                            description="Application log files are publicly accessible. These may contain sensitive information including IP addresses, user data, session tokens, and internal errors.",
                            remediation="Restrict access to log files using server configuration. Store logs outside the web root. Implement proper access controls.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

            except Exception:
                continue

        return vulnerabilities

    async def _check_logging_headers(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for request tracking/correlation headers."""
        parsed = urlparse(endpoint.url)
        path = parsed.path.lower()

        # Only check security-sensitive endpoints
        if not any(action in path for action in SECURITY_ACTIONS):
            return None

        try:
            response = await http_client.get(endpoint.url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for any logging/tracing headers
            has_tracking = any(h in headers for h in LOGGING_HEADERS)

            if not has_tracking:
                return Vulnerability(
                    id=str(uuid4()),
                    name="Missing Request Tracking Headers",
                    severity=SeverityLevel.INFO,
                    owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"Security-sensitive endpoint lacks request tracking headers (X-Request-ID, X-Correlation-ID, etc.).",
                    description="The application doesn't appear to use request tracking for security-sensitive operations. This makes incident investigation and forensics more difficult.",
                    remediation="Implement request correlation IDs for all requests. Include these in logs for traceability. Consider using distributed tracing.",
                    confidence=0.70,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None

    async def _check_debug_endpoints(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for exposed debug endpoints."""
        vulnerabilities = []
        
        parsed = urlparse(endpoint.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        debug_endpoints = [
            ("/debug", "Debug endpoint"),
            ("/debug/", "Debug endpoint"),
            ("/_debug", "Debug endpoint"),
            ("/phpinfo.php", "PHP info"),
            ("/info.php", "PHP info"),
            ("/server-status", "Apache status"),
            ("/server-info", "Apache info"),
            ("/__debug__", "Django debug"),
            ("/actuator", "Spring Boot actuator"),
            ("/actuator/health", "Spring Boot health"),
            ("/actuator/env", "Spring Boot environment"),
            ("/metrics", "Metrics endpoint"),
            ("/health", "Health check"),
            ("/status", "Status endpoint"),
            ("/_profiler", "Symfony profiler"),
            ("/console", "Console endpoint"),
        ]

        check_key = f"{base_url}:debug_endpoints"
        if check_key in self.checked_hosts:
            return []
        self.checked_hosts.add(check_key)

        for path, description in debug_endpoints[:12]:  # Limit checks
            try:
                test_url = urljoin(base_url, path)
                response = await http_client.get(test_url)

                if response.status_code == 200:
                    text = response.text.lower()
                    
                    # Check for debug/internal content
                    debug_indicators = [
                        "debug", "configuration", "environment",
                        "stack trace", "internal", "system info",
                        "phpinfo", "server software", "build info",
                    ]
                    
                    if any(ind in text for ind in debug_indicators) and len(response.text) > 100:
                        severity = SeverityLevel.HIGH if any(s in path for s in ["env", "actuator", "phpinfo"]) else SeverityLevel.MEDIUM
                        
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name=f"Exposed {description}: {path}",
                            severity=severity,
                            owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                            endpoint=test_url,
                            method="GET",
                            parameter=None,
                            evidence=f"{description} accessible at {path}. Exposes internal application details.",
                            description=f"A {description.lower()} is publicly accessible. This exposes internal application configuration, environment variables, or system information.",
                            remediation="Disable or restrict access to debug endpoints in production. Use authentication for admin/debug interfaces.",
                            confidence=0.90,
                            detector_name=self.name,
                        ))

            except Exception:
                continue

        return vulnerabilities

    async def _check_monitoring_indicators(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for signs that security monitoring may be inadequate."""
        parsed = urlparse(endpoint.url)
        path = parsed.path.lower()

        # Only check login/auth endpoints
        if not any(action in path for action in ["login", "signin", "auth"]):
            return None

        try:
            # Send multiple failed requests to check for lockout/monitoring
            failed_attempts = 0
            for i in range(5):
                try:
                    # Simulate failed login attempt pattern
                    response = await http_client.post(
                        endpoint.url,
                        data={"username": f"test_user_{i}", "password": "wrong_password"}
                    )
                    if response.status_code != 429:  # Not rate limited
                        failed_attempts += 1
                except Exception:
                    continue

            if failed_attempts >= 5:
                return Vulnerability(
                    id=str(uuid4()),
                    name="No Apparent Brute Force Protection",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                    endpoint=endpoint.url,
                    method="POST",
                    parameter=None,
                    evidence=f"Sent {failed_attempts} failed authentication attempts without triggering rate limiting or lockout.",
                    description="The authentication endpoint doesn't appear to have brute force protection. This indicates insufficient security monitoring and could allow credential stuffing attacks.",
                    remediation="Implement account lockout after failed attempts. Add rate limiting. Use CAPTCHA after failures. Monitor and alert on suspicious patterns.",
                    confidence=0.75,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None
