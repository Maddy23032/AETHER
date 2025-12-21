"""Cross-Site Scripting (XSS) detection plugin - Enhanced version."""

import html
import re
from typing import List, Optional, Tuple
from uuid import uuid4
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Unique markers for reflection detection
XSS_MARKER = "aether7x3k9z"
XSS_MARKER_TAG = f"<{XSS_MARKER}>"

# Context-aware XSS payloads organized by injection context
XSS_PAYLOADS = {
    # HTML context
    "html": [
        (f"<script>alert('{XSS_MARKER}')</script>", "script_tag", "<script>"),
        (f"<img src=x onerror=alert('{XSS_MARKER}')>", "img_onerror", "onerror="),
        (f"<svg onload=alert('{XSS_MARKER}')>", "svg_onload", "onload="),
        (f"<body onload=alert('{XSS_MARKER}')>", "body_onload", "onload="),
        (f"<iframe src=\"javascript:alert('{XSS_MARKER}')\">", "iframe_js", "javascript:"),
        (f"<div onmouseover=alert('{XSS_MARKER}')>hover</div>", "div_mouseover", "onmouseover="),
        (f"<marquee onstart=alert('{XSS_MARKER}')>", "marquee", "onstart="),
        (f"<details open ontoggle=alert('{XSS_MARKER}')>", "details_toggle", "ontoggle="),
    ],
    # Attribute context (breaking out of attributes)
    "attribute": [
        (f"\" onmouseover=\"alert('{XSS_MARKER}')\" x=\"", "attr_break_double", "onmouseover="),
        (f"' onmouseover='alert(\"{XSS_MARKER}\")' x='", "attr_break_single", "onmouseover="),
        (f"\" onfocus=\"alert('{XSS_MARKER}')\" autofocus=\"", "attr_autofocus", "autofocus"),
        (f"'><script>alert('{XSS_MARKER}')</script><'", "attr_escape_script", "<script>"),
        (f"\"><img src=x onerror=alert('{XSS_MARKER}')>", "attr_escape_img", "onerror="),
    ],
    # JavaScript context
    "javascript": [
        (f"';alert('{XSS_MARKER}');//", "js_single_break", f"alert('{XSS_MARKER}')"),
        (f"\";alert('{XSS_MARKER}');//", "js_double_break", f"alert('{XSS_MARKER}')"),
        (f"</script><script>alert('{XSS_MARKER}')</script>", "js_escape_script", "<script>"),
        (f"-alert('{XSS_MARKER}')-", "js_expression", f"alert('{XSS_MARKER}')"),
    ],
    # URL/href context
    "url": [
        (f"javascript:alert('{XSS_MARKER}')", "javascript_uri", "javascript:alert"),
        (f"data:text/html,<script>alert('{XSS_MARKER}')</script>", "data_uri", "data:text/html"),
        (f"vbscript:alert('{XSS_MARKER}')", "vbscript_uri", "vbscript:"),
    ],
    # Encoding bypass payloads
    "bypass": [
        (f"<ScRiPt>alert('{XSS_MARKER}')</ScRiPt>", "mixed_case", "<script>"),
        (f"<script/x>alert('{XSS_MARKER}')</script>", "tag_slash", "<script"),
        (f"<script\t>alert('{XSS_MARKER}')</script>", "tag_tab", "<script"),
        (f"<<script>alert('{XSS_MARKER}')//<</script>", "nested_tag", "<script>"),
        (f"<img src=x onerror=alert&#40;'{XSS_MARKER}'&#41;>", "html_entity_paren", "onerror="),
        (f"<img src=x onerror=\\u0061lert('{XSS_MARKER}')>", "unicode_escape", "onerror="),
    ],
}

# Headers that should have XSS protection
XSS_PROTECTION_HEADERS = [
    "content-security-policy",
    "x-xss-protection",
    "x-content-type-options",
]


class XSSDetector(BaseDetector):
    """Enhanced Cross-Site Scripting detector with context-aware detection."""

    name = "XSS Detector"
    description = "Detects reflected, stored, and DOM-based XSS with context-aware payloads"

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Test URL parameters
        for param in endpoint.parameters:
            vuln = await self._test_parameter(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test form inputs (text-like inputs only)
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                input_type = inp.get("type", "text").lower()
                if input_type in ["text", "search", "email", "url", "tel", "hidden", ""]:
                    vuln = await self._test_form_input(endpoint, form, inp, http_client)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    async def _test_parameter(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        # First check if input is reflected at all
        try:
            reflection_response = await http_client.get(
                endpoint.url, 
                params={param: XSS_MARKER}
            )
            
            if XSS_MARKER not in reflection_response.text:
                return None  # Not reflected, skip XSS testing
            
            # Detect the reflection context
            context = self._detect_context(reflection_response.text, XSS_MARKER)
            
            # Check for missing XSS protection headers
            has_protection = self._check_xss_headers(reflection_response.headers)
            
        except Exception:
            return None

        # Test payloads appropriate for the detected context
        contexts_to_test = [context, "bypass"] if context else list(XSS_PAYLOADS.keys())
        
        for ctx in contexts_to_test:
            payloads = XSS_PAYLOADS.get(ctx, [])
            for payload, payload_type, indicator in payloads:
                try:
                    response = await http_client.get(
                        endpoint.url, 
                        params={param: payload}
                    )
                    
                    # Check if payload is reflected without proper encoding
                    if self._is_xss_successful(response.text, payload, indicator):
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"Reflected XSS ({payload_type})",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=f"Context: {ctx}. Payload reflected unescaped. Indicator '{indicator}' found in response.",
                            description=f"Reflected Cross-Site Scripting in parameter '{param}'. User input is echoed back without proper output encoding, allowing script injection.",
                            remediation="Implement context-aware output encoding. Use Content-Security-Policy header. Consider using frameworks with automatic escaping.",
                            confidence=0.90 if has_protection else 0.95,
                            detector_name=self.name,
                            raw_request=f"GET {endpoint.url}?{param}={payload[:50]}...",
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
            
        # Check reflection first
        try:
            data = {input_name: XSS_MARKER}
            response = await http_client.post(form["action"], data=data)
            
            if XSS_MARKER not in response.text:
                return None
                
            context = self._detect_context(response.text, XSS_MARKER)
        except Exception:
            return None

        # Test limited payloads for forms
        for ctx in [context or "html", "attribute"]:
            payloads = XSS_PAYLOADS.get(ctx, [])[:3]  # Limit form tests
            for payload, payload_type, indicator in payloads:
                try:
                    data = {input_name: payload}
                    response = await http_client.post(form["action"], data=data)
                    
                    if self._is_xss_successful(response.text, payload, indicator):
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"XSS in Form ({payload_type})",
                            severity=SeverityLevel.HIGH,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            endpoint=form["action"],
                            method="POST",
                            parameter=input_name,
                            evidence=f"Context: {ctx}. XSS payload reflected in form response.",
                            description=f"Cross-Site Scripting in form field '{input_name}'. Form submission reflects input without encoding.",
                            remediation="Encode all form input before rendering. Implement Content-Security-Policy.",
                            confidence=0.85,
                            detector_name=self.name,
                        )
                except Exception:
                    continue
        
        return None

    def _detect_context(self, response_text: str, marker: str) -> Optional[str]:
        """Detect the HTML context where the marker is reflected."""
        idx = response_text.find(marker)
        if idx == -1:
            return None
        
        # Get surrounding context (100 chars before and after)
        start = max(0, idx - 100)
        end = min(len(response_text), idx + len(marker) + 100)
        context_str = response_text[start:end].lower()
        
        # Check if inside script tags
        if "<script" in context_str and "</script>" in context_str:
            return "javascript"
        
        # Check if inside an attribute
        quote_before = context_str.rfind('"', 0, idx - start)
        quote_after = context_str.find('"', idx - start)
        if quote_before != -1 and quote_after != -1:
            # Check for = before the quote (attribute pattern)
            if "=" in context_str[max(0, quote_before - 20):quote_before]:
                return "attribute"
        
        # Check for href/src context (URL context)
        if "href=" in context_str or "src=" in context_str or "url(" in context_str:
            return "url"
        
        # Default to HTML context
        return "html"

    def _is_xss_successful(self, response_text: str, payload: str, indicator: str) -> bool:
        """Check if XSS payload was successfully injected."""
        # The indicator (dangerous part of payload) should be present unencoded
        if indicator.lower() in response_text.lower():
            # Verify it's not HTML-encoded
            encoded_indicator = html.escape(indicator)
            if encoded_indicator != indicator and encoded_indicator in response_text:
                return False  # It's encoded, not vulnerable
            return True
        return False

    def _check_xss_headers(self, headers: dict) -> bool:
        """Check if response has XSS protection headers."""
        header_keys = [h.lower() for h in headers.keys()]
        return any(h in header_keys for h in XSS_PROTECTION_HEADERS)
