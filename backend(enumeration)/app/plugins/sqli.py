"""SQL Injection detection plugin - Enhanced version."""

import asyncio
import time
from typing import List, Optional, Tuple
from uuid import uuid4
from app.plugins.base import BaseDetector
from app.models.scan import DiscoveredEndpoint, Vulnerability, SeverityLevel, OWASPCategory
from app.services.http_client import HttpClient


# Error-based payloads with expected error patterns
ERROR_BASED_PAYLOADS = [
    ("'", "single_quote"),
    ('"', "double_quote"),
    ("'--", "comment_single"),
    ("\"--", "comment_double"),
    ("' OR '1'='1", "or_bypass"),
    ("' OR '1'='1'--", "or_bypass_comment"),
    ("1' AND '1'='1", "and_true"),
    ("1' AND '1'='2", "and_false"),
    ("' UNION SELECT NULL--", "union_null"),
    ("' UNION SELECT NULL,NULL--", "union_null_2"),
    ("' UNION SELECT NULL,NULL,NULL--", "union_null_3"),
    ("1 OR 1=1", "numeric_or"),
    ("1 AND 1=1", "numeric_and"),
    ("') OR ('1'='1", "bracket_bypass"),
    ('admin\'--', "admin_bypass"),
    ("1'; WAITFOR DELAY '0:0:0'--", "mssql_waitfor"),
    ("1' AND SLEEP(0)--", "mysql_sleep_zero"),
]

# Time-based blind SQLi payloads (delay in seconds)
TIME_BASED_PAYLOADS = [
    ("' AND SLEEP(3)--", "mysql_sleep", 3),
    ("' AND SLEEP(3) AND '1'='1", "mysql_sleep_alt", 3),
    ("1' AND (SELECT SLEEP(3))--", "mysql_sleep_select", 3),
    ("'; WAITFOR DELAY '0:0:3'--", "mssql_waitfor", 3),
    ("' AND pg_sleep(3)--", "postgres_sleep", 3),
    ("' || pg_sleep(3)--", "postgres_sleep_concat", 3),
    ("1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--", "postgres_case", 3),
]

# Boolean-based blind SQLi payloads
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2", "and_string"),
    ("' OR '1'='1", "' OR '1'='2", "or_string"),
    ("1 AND 1=1", "1 AND 1=2", "and_numeric"),
    ("1 OR 1=1", "1 OR 1=2", "or_numeric"),
    ("') AND ('1'='1", "') AND ('1'='2", "bracket_and"),
]

# Comprehensive SQL error patterns by database
SQL_ERROR_PATTERNS = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysqli_",
        "mysql_num_rows",
        "mysql_query",
        "supplied argument is not a valid mysql",
        "Column count doesn't match",
        "Unknown column",
        "MySQL server version",
        "SQL syntax.*MySQL",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "postgresql",
        "PSQLException",
        "org.postgresql",
        "ERROR:  syntax error at or near",
        "unterminated quoted string",
        "invalid input syntax for",
    ],
    "mssql": [
        "Microsoft SQL Server",
        "ODBC Driver",
        "SQLServer JDBC",
        "Unclosed quotation mark",
        "mssql_query",
        "Microsoft OLE DB Provider for SQL Server",
        "Incorrect syntax near",
        "SQLSTATE",
        "SQL Server.*Driver",
    ],
    "oracle": [
        "ORA-",
        "Oracle error",
        "Oracle.*Driver",
        "quoted string not properly terminated",
        "SQL command not properly ended",
    ],
    "sqlite": [
        "SQLite3::",
        "sqlite_",
        "SQLite error",
        "SQLITE_ERROR",
        "sqlite3.OperationalError",
        "unrecognized token",
    ],
    "generic": [
        "sql syntax",
        "syntax error",
        "unexpected end of SQL",
        "quoted string not properly terminated",
        "SQL command not properly ended",
        "Invalid SQL",
        "Database error",
        "DB Error",
        "JDBC",
        "database query failed",
    ],
}


class SQLiDetector(BaseDetector):
    """Enhanced SQL Injection detector with multiple detection techniques."""

    name = "SQLi Detector"
    description = "Detects SQL Injection vulnerabilities using error-based, time-based, and boolean-based techniques"

    def __init__(self):
        self.time_threshold = 2.5  # Seconds threshold for time-based detection

    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Test URL parameters
        for param in endpoint.parameters:
            # Error-based detection
            vuln = await self._test_error_based(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
                continue  # Skip other tests if found
            
            # Boolean-based blind detection
            vuln = await self._test_boolean_based(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
                continue
            
            # Time-based blind detection (most expensive, do last)
            vuln = await self._test_time_based(endpoint, param, http_client)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Test form inputs
        for form in endpoint.forms:
            for inp in form.get("inputs", []):
                input_name = inp.get("name")
                if not input_name:
                    continue
                    
                vuln = await self._test_form_error_based(endpoint, form, inp, http_client)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    async def _test_error_based(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for error-based SQL injection."""
        for payload, payload_type in ERROR_BASED_PAYLOADS:
            try:
                response = await http_client.get(
                    endpoint.url,
                    params={param: payload}
                )
                
                db_type, error_found = self._check_sql_error(response.text)
                if error_found:
                    return Vulnerability(
                        id=str(uuid4()),
                        name=f"Error-Based SQL Injection ({payload_type})",
                        severity=SeverityLevel.CRITICAL,
                        owasp_category=OWASPCategory.A03_INJECTION,
                        endpoint=endpoint.url,
                        method="GET",
                        parameter=param,
                        evidence=f"Database: {db_type}. SQL error triggered with payload: {payload}",
                        description=f"Error-based SQL Injection vulnerability found in parameter '{param}'. The application returns database error messages that reveal SQL syntax issues.",
                        remediation="Use parameterized queries (prepared statements) instead of string concatenation. Implement proper input validation and disable detailed error messages in production.",
                        confidence=0.95,
                        detector_name=self.name,
                        raw_request=f"GET {endpoint.url}?{param}={payload}",
                    )
            except Exception:
                continue
        return None

    async def _test_boolean_based(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for boolean-based blind SQL injection."""
        try:
            # Get baseline response
            baseline_response = await http_client.get(endpoint.url, params={param: "1"})
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
        except Exception:
            return None

        for true_payload, false_payload, payload_type in BOOLEAN_PAYLOADS:
            try:
                # Test TRUE condition
                true_response = await http_client.get(
                    endpoint.url,
                    params={param: true_payload}
                )
                
                # Test FALSE condition
                false_response = await http_client.get(
                    endpoint.url,
                    params={param: false_payload}
                )
                
                # Compare responses - looking for different behavior
                true_length = len(true_response.text)
                false_length = len(false_response.text)
                
                # Significant difference suggests boolean-based injection
                length_diff = abs(true_length - false_length)
                if length_diff > 50 and true_response.status_code == false_response.status_code:
                    # Verify it's not just random variation
                    verify_response = await http_client.get(
                        endpoint.url,
                        params={param: true_payload}
                    )
                    if abs(len(verify_response.text) - true_length) < 10:
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"Boolean-Based Blind SQL Injection ({payload_type})",
                            severity=SeverityLevel.CRITICAL,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=f"Response length difference: {length_diff} bytes between TRUE and FALSE conditions",
                            description=f"Boolean-based blind SQL Injection in parameter '{param}'. The application responds differently to TRUE vs FALSE SQL conditions.",
                            remediation="Use parameterized queries. Implement proper input validation. Consider using ORM frameworks.",
                            confidence=0.80,
                            detector_name=self.name,
                        )
            except Exception:
                continue
        return None

    async def _test_time_based(
        self,
        endpoint: DiscoveredEndpoint,
        param: str,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test for time-based blind SQL injection."""
        # First, measure baseline response time
        try:
            start = time.time()
            await http_client.get(endpoint.url, params={param: "1"})
            baseline_time = time.time() - start
        except Exception:
            return None

        for payload, payload_type, expected_delay in TIME_BASED_PAYLOADS[:3]:  # Limit expensive tests
            try:
                start = time.time()
                await http_client.get(
                    endpoint.url,
                    params={param: payload}
                )
                elapsed = time.time() - start
                
                # Check if response was delayed
                if elapsed > baseline_time + self.time_threshold:
                    # Verify with a second request
                    start2 = time.time()
                    await http_client.get(
                        endpoint.url,
                        params={param: payload}
                    )
                    elapsed2 = time.time() - start2
                    
                    if elapsed2 > baseline_time + self.time_threshold:
                        return Vulnerability(
                            id=str(uuid4()),
                            name=f"Time-Based Blind SQL Injection ({payload_type})",
                            severity=SeverityLevel.CRITICAL,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            endpoint=endpoint.url,
                            method="GET",
                            parameter=param,
                            evidence=f"Response delayed by ~{elapsed:.1f}s (baseline: {baseline_time:.1f}s)",
                            description=f"Time-based blind SQL Injection in parameter '{param}'. The database executed a sleep/delay function.",
                            remediation="Use parameterized queries. Implement query timeouts. Use Web Application Firewall.",
                            confidence=0.85,
                            detector_name=self.name,
                        )
            except asyncio.TimeoutError:
                # Timeout might indicate successful injection
                return Vulnerability(
                    id=str(uuid4()),
                    name=f"Possible Time-Based SQL Injection ({payload_type})",
                    severity=SeverityLevel.HIGH,
                    owasp_category=OWASPCategory.A03_INJECTION,
                    endpoint=endpoint.url,
                    method="GET",
                    parameter=param,
                    evidence=f"Request timed out with delay payload",
                    description=f"Possible time-based SQL Injection in '{param}'. Request timed out suggesting delay was executed.",
                    remediation="Use parameterized queries. Investigate manually.",
                    confidence=0.70,
                    detector_name=self.name,
                )
            except Exception:
                continue
        return None

    async def _test_form_error_based(
        self,
        endpoint: DiscoveredEndpoint,
        form: dict,
        inp: dict,
        http_client: HttpClient,
    ) -> Optional[Vulnerability]:
        """Test form inputs for error-based SQL injection."""
        for payload, payload_type in ERROR_BASED_PAYLOADS[:5]:  # Limit form tests
            try:
                data = {inp["name"]: payload}
                method = form.get("method", "POST").upper()
                
                if method == "POST":
                    response = await http_client.post(form["action"], data=data)
                else:
                    response = await http_client.get(form["action"], params=data)
                
                db_type, error_found = self._check_sql_error(response.text)
                if error_found:
                    return Vulnerability(
                        id=str(uuid4()),
                        name=f"SQL Injection in Form ({payload_type})",
                        severity=SeverityLevel.CRITICAL,
                        owasp_category=OWASPCategory.A03_INJECTION,
                        endpoint=form["action"],
                        method=method,
                        parameter=inp["name"],
                        evidence=f"Database: {db_type}. SQL error in form field with payload: {payload}",
                        description=f"SQL Injection in form field '{inp['name']}' at {form['action']}",
                        remediation="Use parameterized queries or prepared statements. Validate all form inputs.",
                        confidence=0.90,
                        detector_name=self.name,
                    )
            except Exception:
                continue
        return None

    def _check_sql_error(self, response_text: str) -> Tuple[str, bool]:
        """Check response for SQL error patterns. Returns (db_type, found)."""
        lower_text = response_text.lower()
        
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in lower_text:
                    return (db_type, True)
        
        return ("unknown", False)
