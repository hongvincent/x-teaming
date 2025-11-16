"""
Compliance Enforcement Module
Validates cloud configurations against compliance standards
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ComplianceViolation:
    """Compliance violation finding"""

    violation_id: str
    standard: str
    control_id: str
    severity: str
    resource: str
    description: str
    remediation: str


@dataclass
class ComplianceReport:
    """Compliance assessment report"""

    standard: str
    report_id: str
    timestamp: str
    total_controls: int
    passed: int
    failed: int
    compliance_score: float
    violations: List[ComplianceViolation]
    recommendations: List[str]


class ComplianceEnforcementModule:
    """
    Compliance Enforcement Module
    Validates against GDPR, SOC2, HIPAA, PCI-DSS, etc.
    """

    def __init__(self):
        """Initialize compliance enforcement module"""
        self.llm_client = LLMClient()
        logger.info("Compliance Enforcement Module initialized")

    def validate_compliance(self, config: Dict[str, Any], standard: str) -> ComplianceReport:
        """Validate configuration against compliance standard"""
        logger.info(f"Validating {standard} compliance")

        system_message = f"""You are a {standard} compliance expert.
Assess configurations against {standard} requirements.
Identify violations and provide remediation guidance."""

        config_str = "\n".join([f"{k}: {v}" for k, v in config.items()])

        prompt = f"""Assess this configuration for {standard} compliance:

Configuration:
{config_str}

Provide compliance assessment in JSON format:
{{
    "total_controls": number of controls assessed,
    "passed": controls passed,
    "failed": controls failed,
    "compliance_score": float (0-100),
    "violations": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "control_id": "control identifier",
            "resource": "affected resource",
            "description": "violation description",
            "remediation": "how to remediate"
        }}
    ],
    "recommendations": [compliance recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            violations = []
            for viol in result.get("violations", []):
                violations.append(
                    ComplianceViolation(
                        violation_id=f"viol_{len(violations)}",
                        standard=standard,
                        control_id=viol.get("control_id", ""),
                        severity=viol.get("severity", "MEDIUM"),
                        resource=viol.get("resource", ""),
                        description=viol.get("description", ""),
                        remediation=viol.get("remediation", ""),
                    )
                )

            return ComplianceReport(
                standard=standard,
                report_id=f"compliance_{datetime.now().timestamp()}",
                timestamp=datetime.now().isoformat(),
                total_controls=result.get("total_controls", 0),
                passed=result.get("passed", 0),
                failed=result.get("failed", 0),
                compliance_score=result.get("compliance_score", 0.0),
                violations=violations,
                recommendations=result.get("recommendations", []),
            )
        except Exception as e:
            logger.error(f"Compliance validation failed: {e}")
            return ComplianceReport(
                standard=standard,
                report_id="error",
                timestamp=datetime.now().isoformat(),
                total_controls=0,
                passed=0,
                failed=0,
                compliance_score=0.0,
                violations=[],
                recommendations=[f"Validation error: {e}"],
            )


# Example usage
if __name__ == "__main__":
    enforcer = ComplianceEnforcementModule()

    config = {
        "encryption": "enabled",
        "logging": "disabled",
        "data_retention": "indefinite",
        "access_controls": "basic",
    }

    report = enforcer.validate_compliance(config, "GDPR")
    print(f"Standard: {report.standard}")
    print(f"Compliance Score: {report.compliance_score:.1f}%")
    print(f"Passed: {report.passed}/{report.total_controls}")
    print(f"Violations: {len(report.violations)}")
