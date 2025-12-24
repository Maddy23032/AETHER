"""Authentication Failures detection plugin - OWASP A07:2021."""

import re
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urlparse
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Weak password policy indicators
WEAK_PASSWORD_PATTERNS = [
    (r'minlength=["\']?([1-5])["\']?', "Minimum password length too short"),
    (r'maxlength=["\']?([1-9]|1[0-5])["\']?', "Maximum password length too restrictive"),
    (r'pattern=["\']?\^?\[?[a-z0-9]+\]?\*?\$?["\']?', "Password pattern allows weak passwords"),
]

# Session management issues
SESSION_ISSUES = {
    "session_in_url": [
        r'[?&;](session|sess|sid|phpsessid|jsessionid|aspsessionid|token)=',
    ],
    "predictable_session": [
        r'session_id=[0-9]+$',
        r'sid=[0-9]{1,10}$',
    ],
}

# Default credentials to check
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("administrator", "administrator"),
]

# Authentication bypass patterns
AUTH_BYPASS_PATTERNS = [
    # SQL injection in auth
    ("admin' --", "SQL injection bypass"),
    ("admin'/*", "SQL injection bypass"),
    ("' OR '1'='1", "SQL injection bypass"),
    ("' OR 1=1--", "SQL injection bypass"),
    # NoSQL injection
    ('{"$gt":""}', "NoSQL injection bypass"),
    ('admin",$or:[{},{"a":"a', "NoSQL injection bypass"),
]


class AuthFailuresDetector(BaseDetector):
    """Detects Authentication Failures (OWASP A07:2021)."""

    name = "Authentication Failures Detector"
    description = "Detects weak authentication, session management issues, and credential vulnerabilities"

    def __init__(self):
        self.tested_endpoints: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Check for weak password policies
        vuln = await self._check_password_policy(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check session management
        session_vulns = await self._check_session_management(endpoint, http_client)
        vulnerabilities.extend(session_vulns)

        # Check for missing authentication headers
        vuln = await self._check_auth_headers(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for credential exposure
        vuln = await self._check_credential_exposure(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for insecure "remember me"
        vuln = await self._check_remember_me(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for password autocomplete
        vuln = await self._check_autocomplete(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for multi-factor authentication absence
        vuln = await self._check_mfa_absence(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_password_policy(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for weak password policy indicators."""
        issues = []

        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                if inp.get("type") == "password":
                    name = inp.get("name", "password")
                    
                    # Check minlength
                    minlength = inp.get("minlength")
                    if minlength and int(minlength) < 8:
                        issues.append(f"Minimum password length is only {minlength} characters")

                    # Check maxlength
                    maxlength = inp.get("maxlength")
                    if maxlength and int(maxlength) < 20:
                        issues.append(f"Maximum password length restricted to {maxlength} characters")

                    # Check for pattern
                    pattern = inp.get("pattern")
                    if pattern:
                        # Check if pattern is too simple
                        if not re.search(r'[A-Z]', pattern) and not re.search(r'[!@#$%^&*]', pattern):
                            issues.append("Password pattern doesn't require uppercase or special characters")

        if issues:
            return Vulnerability(
                id=str(uuid4()),
                name="Weak Password Policy",
                severity=SeverityLevel.MEDIUM,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                endpoint=endpoint.url,
                method="GET",
                parameter=None,
                evidence=f"Password policy issues: {'; '.join(issues)}",
                description="The password policy allows weak passwords that can be easily brute-forced or guessed.",
                remediation="Enforce minimum 12 characters, require mixed case, numbers, and special characters. Remove maximum length restrictions. Consider using password strength meters.",
                confidence=0.85,
                detector_name=self.name,
            )

        return None

    async def _check_session_management(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Check for session management vulnerabilities."""
        vulnerabilities = []

        try:
            response = await http_client.get(endpoint.url)

            # Check for session ID in URL
            if any(re.search(p, endpoint.url, re.IGNORECASE) for p in SESSION_ISSUES["session_in_url"]):
                vulnerabilities.append(Vulnerability(
                    id=str(uuid4()),
                    name="Session ID in URL",
                    severity=SeverityLevel.HIGH,
                    owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter="URL",
                    evidence="Session identifier appears in the URL. This exposes the session to logs, referrer headers, and browser history.",
                    description="Passing session tokens in URLs is insecure. They can be leaked through referrer headers, browser history, logs, and shared links.",
                    remediation="Use cookies with HttpOnly and Secure flags for session management. Never include session tokens in URLs.",
                    confidence=0.95,
                    detector_name=self.name,
                ))

            # Check for predictable session IDs
            cookies = response.headers.get("set-cookie", "")
            session_patterns = [
                (r'(session|sess|sid)=([0-9]+)', "Numeric session ID"),
                (r'(session|sess|sid)=([a-f0-9]{8})$', "Short hex session ID"),
            ]
            
            for pattern, description in session_patterns:
                match = re.search(pattern, cookies, re.IGNORECASE)
                if match:
                    vulnerabilities.append(Vulnerability(
                        id=str(uuid4()),
                        name="Potentially Predictable Session ID",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=match.group(1),
                        evidence=f"{description} detected: {match.group(2)[:20]}...",
                        description="The session ID format appears to be predictable or has insufficient entropy. Attackers may be able to guess valid session IDs.",
                        remediation="Use cryptographically secure random session IDs with at least 128 bits of entropy.",
                        confidence=0.70,
                        detector_name=self.name,
                    ))
                    break

            # Check for session fixation indicators
            if "set-cookie" in response.headers and "session" in response.headers.get("set-cookie", "").lower():
                # Check if session is set before authentication
                has_login_form = any(
                    any(inp.get("type") == "password" for inp in form.get("inputs", []))
                    for form in endpoint.forms
                )
                if has_login_form:
                    # Pre-auth session cookie - potential fixation
                    if "samesite" not in cookies.lower():
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Potential Session Fixation",
                            severity=SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=None,
                            evidence="Session cookie is set before authentication and lacks SameSite attribute.",
                            description="Session cookies set before login may be vulnerable to session fixation attacks if not regenerated after authentication.",
                            remediation="Regenerate session ID after successful authentication. Add SameSite=Strict to session cookies.",
                            confidence=0.70,
                            detector_name=self.name,
                        ))

        except Exception:
            pass

        return vulnerabilities

    async def _check_auth_headers(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for missing security headers related to authentication."""
        parsed = urlparse(endpoint.url)
        
        # Only check login pages
        if not any(p in parsed.path.lower() for p in ["/login", "/signin", "/auth", "/account"]):
            return None

        try:
            response = await http_client.get(endpoint.url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            issues = []

            # Check for X-Frame-Options (clickjacking on login)
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                issues.append("Missing X-Frame-Options (clickjacking risk on login)")

            # Check Cache-Control for sensitive page
            cache_control = headers.get("cache-control", "")
            if "no-store" not in cache_control and "private" not in cache_control:
                issues.append("Login page may be cached (Cache-Control should include no-store)")

            if issues:
                return Vulnerability(
                    id=str(uuid4()),
                    name="Missing Security Headers on Authentication Page",
                    severity=SeverityLevel.LOW,
                    owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"Security header issues: {'; '.join(issues)}",
                    description="The authentication page is missing important security headers that protect against common attacks.",
                    remediation="Add X-Frame-Options: DENY, Cache-Control: no-store, private. Consider implementing CSP.",
                    confidence=0.85,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None

    async def _check_credential_exposure(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for exposed credentials in response."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text

            # Look for hardcoded credentials
            credential_patterns = [
                (r'password\s*[=:]\s*["\']([^"\']{3,})["\']', "Hardcoded password"),
                (r'passwd\s*[=:]\s*["\']([^"\']{3,})["\']', "Hardcoded password"),
                (r'api[_-]?key\s*[=:]\s*["\']([^"\']{10,})["\']', "Exposed API key"),
                (r'secret\s*[=:]\s*["\']([^"\']{10,})["\']', "Exposed secret"),
                (r'auth[_-]?token\s*[=:]\s*["\']([^"\']{10,})["\']', "Exposed auth token"),
                (r'bearer\s+([a-zA-Z0-9._-]{20,})', "Exposed bearer token"),
            ]

            for pattern, description in credential_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    # Mask the credential
                    cred = match.group(1)
                    masked = cred[:3] + "***" + cred[-2:] if len(cred) > 5 else "***"
                    
                    return Vulnerability(
                        id=str(uuid4()),
                        name="Credentials Exposed in Response",
                        severity=SeverityLevel.HIGH,
                        owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"{description} found in response: {masked}",
                        description="Credentials or secrets are exposed in the page source. This could allow attackers to gain unauthorized access.",
                        remediation="Remove all hardcoded credentials from client-side code. Use secure server-side configuration management.",
                        confidence=0.85,
                        detector_name=self.name,
                    )

        except Exception:
            pass

        return None

    async def _check_remember_me(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for insecure 'remember me' implementations."""
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").lower()
                inp_type = inp.get("type", "").lower()

                if inp_type == "checkbox" and any(r in name for r in ["remember", "keeplogin", "persist", "autologin"]):
                    # Check if there's a password field (login form)
                    has_password = any(
                        i.get("type") == "password"
                        for i in form.get("inputs", [])
                    )
                    
                    if has_password:
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Remember Me Functionality Detected",
                            severity=SeverityLevel.LOW,
                            owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=name,
                            evidence=f"Remember me checkbox found: '{name}'",
                            description="'Remember me' functionality extends session duration, increasing the window for session hijacking. Insecure implementations may store credentials client-side.",
                            remediation="Implement 'remember me' securely using encrypted tokens. Limit extended session duration. Require re-authentication for sensitive operations.",
                            confidence=0.80,
                            detector_name=self.name,
                        )

        return None

    async def _check_autocomplete(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for password autocomplete enabled."""
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                if inp.get("type") == "password":
                    autocomplete = inp.get("autocomplete", "").lower()
                    
                    # If autocomplete is not explicitly disabled
                    if autocomplete not in ["off", "new-password", "current-password"]:
                        return Vulnerability(
                            id=str(uuid4()),
                            name="Password Autocomplete Enabled",
                            severity=SeverityLevel.INFO,
                            owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=inp.get("name", "password"),
                            evidence=f"Password field does not have autocomplete='off' or secure autocomplete values.",
                            description="Browser may store password in autocomplete. On shared computers, this poses a risk. Modern guidance suggests using autocomplete='current-password' for security and usability balance.",
                            remediation="Set autocomplete='current-password' for existing password fields and 'new-password' for password creation. Consider the trade-off with password manager usability.",
                            confidence=0.90,
                            detector_name=self.name,
                        )

        return None

    async def _check_mfa_absence(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Check for absence of MFA on login pages."""
        parsed = urlparse(endpoint.url)
        path = parsed.path.lower()

        # Only check login pages
        if not any(p in path for p in ["/login", "/signin", "/auth"]):
            return None

        try:
            response = await http_client.get(endpoint.url)
            text = response.text.lower()

            # Look for MFA indicators
            mfa_patterns = [
                r'two.?factor', r'2fa', r'mfa', r'multi.?factor',
                r'authenticator', r'verification\s*code', r'otp',
                r'sms\s*code', r'security\s*code', r'backup\s*code',
                r'totp', r'google\s*authenticator', r'authy',
            ]

            has_mfa = any(re.search(p, text) for p in mfa_patterns)

            if not has_mfa:
                # Check if it's a significant login page
                has_login_form = any(
                    any(inp.get("type") == "password" for inp in form.get("inputs", []))
                    for form in endpoint.forms
                )

                if has_login_form:
                    return Vulnerability(
                        id=str(uuid4()),
                        name="Multi-Factor Authentication Not Detected",
                        severity=SeverityLevel.INFO,
                        owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="Login page does not show evidence of MFA/2FA implementation.",
                        description="The login page does not appear to use multi-factor authentication. Single-factor authentication is more vulnerable to credential theft and brute force attacks.",
                        remediation="Implement MFA using TOTP apps, SMS codes, or hardware tokens. Consider risk-based authentication for additional security.",
                        confidence=0.70,
                        detector_name=self.name,
                    )

        except Exception:
            pass

        return None
