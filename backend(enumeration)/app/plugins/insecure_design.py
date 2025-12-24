"""Insecure Design detection plugin - OWASP A04:2021."""

import re
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urljoin, urlparse
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Business logic flaw indicators
BUSINESS_LOGIC_PATTERNS = {
    "price_manipulation": [
        r"price[\"']?\s*[:=]", r"amount[\"']?\s*[:=]", r"cost[\"']?\s*[:=]",
        r"total[\"']?\s*[:=]", r"discount[\"']?\s*[:=]", r"coupon",
    ],
    "quantity_bypass": [
        r"quantity[\"']?\s*[:=]", r"qty[\"']?\s*[:=]", r"count[\"']?\s*[:=]",
        r"limit[\"']?\s*[:=]", r"max[\"']?\s*[:=]",
    ],
    "workflow_bypass": [
        r"step[\"']?\s*[:=]", r"stage[\"']?\s*[:=]", r"status[\"']?\s*[:=]",
        r"state[\"']?\s*[:=]", r"phase[\"']?\s*[:=]",
    ],
}

# Rate limiting test endpoints
RATE_LIMIT_ENDPOINTS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/register", "/signup", "/forgot-password", "/reset-password",
    "/api/login", "/api/auth", "/api/register",
    "/contact", "/feedback", "/comment", "/review",
    "/otp", "/verify", "/confirm", "/validate",
]

# CAPTCHA bypass indicators
CAPTCHA_PATTERNS = [
    r"captcha", r"recaptcha", r"hcaptcha", r"turnstile",
    r"g-recaptcha", r"cf-turnstile", r"h-captcha",
]

# Security question weaknesses
SECURITY_QUESTION_PATTERNS = [
    r"security.?question", r"secret.?question", r"recovery.?question",
    r"mother.?maiden", r"first.?pet", r"favorite.?color",
    r"born.?city", r"high.?school",
]


class InsecureDesignDetector(BaseDetector):
    """Detects Insecure Design vulnerabilities (OWASP A04:2021)."""

    name = "Insecure Design Detector"
    description = "Detects business logic flaws, missing rate limiting, CAPTCHA issues, and design vulnerabilities"

    def __init__(self):
        self.tested_endpoints: set = set()

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []

        # Test for missing rate limiting
        vuln = await self._test_rate_limiting(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Test for CAPTCHA bypass
        vuln = await self._test_captcha_bypass(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Test for business logic flaws in forms
        logic_vulns = await self._test_business_logic(endpoint, http_client)
        vulnerabilities.extend(logic_vulns)

        # Check for insecure password reset
        vuln = await self._test_password_reset_flaws(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for enumeration vulnerabilities
        vuln = await self._test_user_enumeration(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for insecure security questions
        vuln = await self._test_security_questions(endpoint, http_client)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_rate_limiting(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for missing rate limiting on sensitive endpoints."""
        parsed = urlparse(endpoint.url)
        path = parsed.path.lower()

        # Check if this is a sensitive endpoint
        is_sensitive = any(p in path for p in RATE_LIMIT_ENDPOINTS)
        has_login_form = any(
            any(inp.get("type") == "password" for inp in form.get("inputs", []))
            for form in endpoint.forms
        )

        if not is_sensitive and not has_login_form:
            return None

        # Prevent duplicate testing
        test_key = f"rate_limit:{parsed.netloc}{parsed.path}"
        if test_key in self.tested_endpoints:
            return None
        self.tested_endpoints.add(test_key)

        try:
            # Send multiple rapid requests
            request_count = 10
            success_count = 0
            
            for i in range(request_count):
                try:
                    response = await http_client.get(endpoint.url)
                    if response.status_code in [200, 401, 403]:
                        success_count += 1
                    elif response.status_code == 429:
                        # Rate limiting is active
                        return None
                except Exception:
                    continue

            # If all requests succeeded, rate limiting may be missing
            if success_count == request_count:
                return Vulnerability(
                    id=str(uuid4()),
                    name="Missing Rate Limiting",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"Sent {request_count} rapid requests to sensitive endpoint. All succeeded without rate limiting (no HTTP 429).",
                    description="This sensitive endpoint lacks rate limiting protection. Attackers can perform brute force attacks, credential stuffing, or abuse the functionality.",
                    remediation="Implement rate limiting using techniques like token bucket or sliding window. Consider using WAF rules. Add CAPTCHA after failed attempts.",
                    confidence=0.80,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None

    async def _test_captcha_bypass(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for CAPTCHA bypass vulnerabilities."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text.lower()

            # Check if page has CAPTCHA
            has_captcha = any(
                re.search(pattern, text, re.IGNORECASE)
                for pattern in CAPTCHA_PATTERNS
            )

            if not has_captcha:
                return None

            # Check for common CAPTCHA bypass indicators
            bypass_indicators = []

            # Look for hidden CAPTCHA tokens that might be static
            static_token = re.search(r'captcha[_-]?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', text)
            if static_token:
                bypass_indicators.append("Static CAPTCHA token found in source")

            # Check if CAPTCHA is only client-side validated
            for form in endpoint.forms:
                captcha_field = None
                for inp in form.get("inputs", []):
                    name = inp.get("name", "").lower()
                    if any(c in name for c in ["captcha", "recaptcha", "verify"]):
                        captcha_field = inp
                        break

                if captcha_field:
                    # Check if field is optional (no required attribute)
                    if not captcha_field.get("required"):
                        bypass_indicators.append(f"CAPTCHA field '{captcha_field.get('name')}' is not marked as required")

            if bypass_indicators:
                return Vulnerability(
                    id=str(uuid4()),
                    name="Potential CAPTCHA Bypass",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"CAPTCHA implementation issues: {'; '.join(bypass_indicators)}",
                    description="The CAPTCHA implementation may be bypassable. This allows automated attacks and bot abuse.",
                    remediation="Use server-side CAPTCHA validation. Integrate with reCAPTCHA v3 or similar services. Never trust client-side validation alone.",
                    confidence=0.70,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None

    async def _test_business_logic(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """Test for business logic vulnerabilities in forms."""
        vulnerabilities = []

        for form in endpoint.forms:
            form_inputs = {
                inp.get("name"): inp 
                for inp in form.get("inputs", []) 
                if inp.get("name")
            }

            # Check for price/amount fields that could be manipulated
            for name, inp in form_inputs.items():
                name_lower = name.lower()
                
                # Check for hidden price fields
                if inp.get("type") == "hidden":
                    if any(p in name_lower for p in ["price", "amount", "total", "cost"]):
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Client-Side Price Control",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            endpoint=endpoint.url,
                            method="POST",
                            parameter=name,
                            evidence=f"Hidden form field '{name}' with value '{inp.get('value', '')}' controls pricing. This can be manipulated by attackers.",
                            description="Price or amount values are stored in client-side hidden fields. Attackers can modify these values to manipulate prices, totals, or discounts.",
                            remediation="Never trust client-side price data. Calculate all prices server-side. Validate that submitted prices match server-side calculations.",
                            confidence=0.85,
                            detector_name=self.name,
                        ))

                # Check for workflow/state fields
                if any(p in name_lower for p in ["step", "stage", "status", "state", "phase"]):
                    if inp.get("type") == "hidden" or inp.get("value"):
                        vulnerabilities.append(Vulnerability(
                            id=str(uuid4()),
                            name="Client-Side Workflow Control",
                            severity=SeverityLevel.MEDIUM,
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            endpoint=endpoint.url,
                            method="POST",
                            parameter=name,
                            evidence=f"Form field '{name}' controls workflow state (value: '{inp.get('value', '')}').",
                            description="Workflow or process state is controlled via client-side form fields. Attackers can skip steps or manipulate the process flow.",
                            remediation="Track workflow state server-side using sessions. Validate state transitions on the server. Never trust client-submitted state values.",
                            confidence=0.75,
                            detector_name=self.name,
                        ))

            # Check for unlimited quantity fields
            for name, inp in form_inputs.items():
                if any(p in name.lower() for p in ["quantity", "qty", "count", "amount"]):
                    if inp.get("type") == "number" or inp.get("type") == "text":
                        # Check if there's no max constraint
                        if not inp.get("max"):
                            vulnerabilities.append(Vulnerability(
                                id=str(uuid4()),
                                name="Unconstrained Quantity Field",
                                severity=SeverityLevel.LOW,
                                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                                endpoint=endpoint.url,
                                method="POST",
                                parameter=name,
                                evidence=f"Quantity field '{name}' has no maximum value constraint.",
                                description="Quantity or count fields lack maximum value constraints. This could allow abuse like ordering negative quantities or extremely large amounts.",
                                remediation="Set reasonable min/max constraints on quantity fields. Validate all quantities server-side.",
                                confidence=0.65,
                                detector_name=self.name,
                            ))

        return vulnerabilities

    async def _test_password_reset_flaws(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for insecure password reset implementations."""
        path = urlparse(endpoint.url).path.lower()
        
        if not any(p in path for p in ["reset", "forgot", "recover", "restore"]):
            return None

        try:
            response = await http_client.get(endpoint.url)
            text = response.text.lower()

            issues = []

            # Check for token in URL
            if re.search(r'[?&]token=', endpoint.url.lower()):
                issues.append("Reset token exposed in URL (visible in logs, referrer headers)")

            # Check for security questions (weak recovery)
            if any(re.search(p, text) for p in SECURITY_QUESTION_PATTERNS):
                issues.append("Uses security questions for recovery (easily guessable)")

            # Check for email/username enumeration hints
            enumeration_hints = [
                r"email\s*not\s*found", r"user\s*not\s*found",
                r"account\s*not\s*found", r"invalid\s*email",
                r"no\s*account\s*with", r"doesn't\s*exist",
            ]
            if any(re.search(p, text) for p in enumeration_hints):
                issues.append("Error messages reveal if email/username exists")

            if issues:
                return Vulnerability(
                    id=str(uuid4()),
                    name="Insecure Password Reset Design",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence=f"Password reset security issues: {'; '.join(issues)}",
                    description="The password reset mechanism has security design flaws that could allow account takeover or user enumeration.",
                    remediation="Use time-limited, single-use tokens. Send tokens via POST body, not URL. Use consistent error messages. Avoid security questions.",
                    confidence=0.80,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None

    async def _test_user_enumeration(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for user enumeration vulnerabilities."""
        path = urlparse(endpoint.url).path.lower()
        
        if not any(p in path for p in ["login", "signin", "register", "signup", "forgot"]):
            return None

        # Check for username/email field
        has_username_field = any(
            any(inp.get("name", "").lower() in ["username", "email", "user", "login"]
                for inp in form.get("inputs", []))
            for form in endpoint.forms
        )

        if not has_username_field:
            return None

        try:
            response = await http_client.get(endpoint.url)
            text = response.text.lower()

            # Look for different error message patterns
            enumeration_patterns = [
                (r"invalid\s*password", "Password-specific error"),
                (r"password\s*incorrect", "Password-specific error"),
                (r"wrong\s*password", "Password-specific error"),
                (r"user(name)?\s*not\s*found", "Username existence revealed"),
                (r"email\s*not\s*registered", "Email existence revealed"),
                (r"account\s*does\s*not\s*exist", "Account existence revealed"),
                (r"no\s*user\s*with\s*that", "User existence revealed"),
            ]

            for pattern, description in enumeration_patterns:
                if re.search(pattern, text):
                    return Vulnerability(
                        id=str(uuid4()),
                        name="User Enumeration via Error Messages",
                        severity=SeverityLevel.LOW,
                        owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence=f"Error message pattern detected: '{description}'",
                        description="The application reveals whether a user account exists through different error messages. This allows attackers to enumerate valid usernames.",
                        remediation="Use generic error messages like 'Invalid credentials' for all authentication failures. Implement account lockout and monitoring.",
                        confidence=0.75,
                        detector_name=self.name,
                    )

        except Exception:
            pass

        return None

    async def _test_security_questions(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for insecure security question implementations."""
        try:
            response = await http_client.get(endpoint.url)
            text = response.text.lower()

            # Look for security question patterns
            has_security_questions = any(
                re.search(pattern, text)
                for pattern in SECURITY_QUESTION_PATTERNS
            )

            if has_security_questions:
                # Check if answers are in dropdown (limited options = very weak)
                if re.search(r'<select[^>]*security|question', text):
                    return Vulnerability(
                        id=str(uuid4()),
                        name="Weak Security Questions with Limited Answers",
                        severity=SeverityLevel.MEDIUM,
                        owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=None,
                        evidence="Security questions use dropdown menus with predefined answers, making them trivially guessable.",
                        description="Security questions with limited answer options provide almost no security. They can be easily brute-forced or guessed.",
                        remediation="Avoid security questions entirely. Use multi-factor authentication, email-based recovery, or authenticator apps instead.",
                        confidence=0.90,
                        detector_name=self.name,
                    )

                # General security question warning
                return Vulnerability(
                    id=str(uuid4()),
                    name="Security Questions in Use",
                    severity=SeverityLevel.LOW,
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=None,
                    evidence="Application uses security questions for account recovery or verification.",
                    description="Security questions are inherently weak. Answers are often publicly available (social media), guessable, or forgettable.",
                    remediation="Replace security questions with modern authentication methods: MFA, email/SMS verification, or authenticator apps.",
                    confidence=0.85,
                    detector_name=self.name,
                )

        except Exception:
            pass

        return None
