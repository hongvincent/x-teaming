"""
Cloud Misconfiguration Detection Module
Detects security misconfigurations in cloud infrastructure
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Misconfiguration:
    """Cloud misconfiguration finding"""

    config_id: str
    severity: str
    resource_type: str
    resource_id: str
    issue: str
    description: str
    impact: str
    remediation: str
    compliance_violations: List[str]


@dataclass
class CloudAuditReport:
    """Cloud security audit report"""

    cloud_provider: str
    audit_id: str
    timestamp: str
    resources_scanned: int
    misconfigurations_found: int
    critical_count: int
    high_count: int
    findings: List[Misconfiguration]
    security_score: float
    recommendations: List[str]


class MisconfigurationDetectionModule:
    """
    Cloud Misconfiguration Detection Module
    Detects security misconfigurations in AWS, Azure, GCP, Kubernetes
    """

    def __init__(self):
        """Initialize misconfiguration detection module"""
        self.llm_client = LLMClient()
        logger.info("Misconfiguration Detection Module initialized")

    def analyze_aws_config(self, aws_config: Dict[str, Any]) -> CloudAuditReport:
        """Analyze AWS configuration"""
        logger.info("Analyzing AWS configuration")

        system_message = """You are an AWS security expert.
Detect misconfigurations:
- Overly permissive IAM policies
- Public S3 buckets
- Open security groups
- Unencrypted resources
- Missing logging/monitoring
- Default VPC usage
- Exposed databases"""

        config_str = "\n".join([f"{k}: {v}" for k, v in aws_config.items()])

        prompt = f"""Analyze this AWS configuration for security issues:

{config_str}

Provide analysis in JSON format:
{{
    "resources_scanned": total count,
    "security_score": float (0-100),
    "misconfigurations": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "resource_type": "s3" | "iam" | "ec2" | "rds" | "sg",
            "resource_id": "resource identifier",
            "issue": "brief issue description",
            "description": "detailed description",
            "impact": "security impact",
            "remediation": "how to fix",
            "compliance_violations": ["CIS", "NIST", etc.]
        }}
    ],
    "recommendations": [overall recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            return self._build_audit_report("AWS", result)
        except Exception as e:
            logger.error(f"AWS config analysis failed: {e}")
            return self._empty_audit_report("AWS", str(e))

    def analyze_kubernetes_config(self, k8s_config: Dict[str, Any]) -> CloudAuditReport:
        """Analyze Kubernetes configuration"""
        logger.info("Analyzing Kubernetes configuration")

        system_message = """You are a Kubernetes security expert.
Detect misconfigurations:
- Privileged containers
- Host network/PID access
- Missing security contexts
- Overly permissive RBAC
- Exposed secrets
- Missing resource limits
- Insecure API server"""

        config_str = "\n".join([f"{k}: {v}" for k, v in k8s_config.items()])

        prompt = f"""Analyze this Kubernetes configuration:

{config_str}

Provide analysis in JSON format:
{{
    "resources_scanned": count,
    "security_score": float (0-100),
    "misconfigurations": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "resource_type": "pod" | "deployment" | "service" | "rbac",
            "resource_id": "resource name",
            "issue": "issue description",
            "description": "detailed description",
            "impact": "security impact",
            "remediation": "fix instructions",
            "compliance_violations": ["CIS Kubernetes", "NSA/CISA"]
        }}
    ],
    "recommendations": [recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            return self._build_audit_report("Kubernetes", result)
        except Exception as e:
            logger.error(f"K8s config analysis failed: {e}")
            return self._empty_audit_report("Kubernetes", str(e))

    def detect_exposed_resources(self, cloud_resources: List[Dict[str, Any]]) -> List[Misconfiguration]:
        """Detect publicly exposed resources"""
        logger.info(f"Scanning {len(cloud_resources)} resources for exposure")

        system_message = """You are a cloud security specialist.
Identify publicly exposed resources that shouldn't be:
- Public databases
- Open storage buckets
- Exposed admin interfaces
- Public API endpoints
- Accessible management ports"""

        resources_str = "\n".join([str(r) for r in cloud_resources[:10]])

        prompt = f"""Identify publicly exposed resources:

Resources:
{resources_str}

Provide findings in JSON format:
{{
    "exposed_resources": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "resource_type": "type",
            "resource_id": "id",
            "issue": "exposure type",
            "description": "description",
            "impact": "impact",
            "remediation": "fix",
            "compliance_violations": []
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            findings = []
            for misc in result.get("exposed_resources", []):
                findings.append(
                    Misconfiguration(
                        config_id=f"exposed_{len(findings)}",
                        severity=misc.get("severity", "MEDIUM"),
                        resource_type=misc.get("resource_type", ""),
                        resource_id=misc.get("resource_id", ""),
                        issue=misc.get("issue", ""),
                        description=misc.get("description", ""),
                        impact=misc.get("impact", ""),
                        remediation=misc.get("remediation", ""),
                        compliance_violations=misc.get("compliance_violations", []),
                    )
                )
            return findings
        except Exception as e:
            logger.error(f"Exposure detection failed: {e}")
            return []

    def _build_audit_report(self, provider: str, result: Dict[str, Any]) -> CloudAuditReport:
        """Build audit report from results"""
        findings = []
        for misc in result.get("misconfigurations", []):
            findings.append(
                Misconfiguration(
                    config_id=f"config_{len(findings)}",
                    severity=misc.get("severity", "MEDIUM"),
                    resource_type=misc.get("resource_type", ""),
                    resource_id=misc.get("resource_id", ""),
                    issue=misc.get("issue", ""),
                    description=misc.get("description", ""),
                    impact=misc.get("impact", ""),
                    remediation=misc.get("remediation", ""),
                    compliance_violations=misc.get("compliance_violations", []),
                )
            )

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        return CloudAuditReport(
            cloud_provider=provider,
            audit_id=f"audit_{datetime.now().timestamp()}",
            timestamp=datetime.now().isoformat(),
            resources_scanned=result.get("resources_scanned", 0),
            misconfigurations_found=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            findings=findings,
            security_score=result.get("security_score", 0.0),
            recommendations=result.get("recommendations", []),
        )

    def _empty_audit_report(self, provider: str, error: str) -> CloudAuditReport:
        """Create empty audit report on error"""
        return CloudAuditReport(
            cloud_provider=provider,
            audit_id="error",
            timestamp=datetime.now().isoformat(),
            resources_scanned=0,
            misconfigurations_found=0,
            critical_count=0,
            high_count=0,
            findings=[],
            security_score=0.0,
            recommendations=[f"Analysis error: {error}"],
        )


# Example usage
if __name__ == "__main__":
    detector = MisconfigurationDetectionModule()

    aws_config = {
        "s3_buckets": [
            {"name": "public-bucket", "public_access": True, "encryption": False}
        ],
        "security_groups": [
            {"id": "sg-123", "ingress": [{"port": 22, "source": "0.0.0.0/0"}]}
        ],
    }

    print("=" * 70)
    print("AWS MISCONFIGURATION DETECTION")
    print("=" * 70)

    report = detector.analyze_aws_config(aws_config)
    print(f"Provider: {report.cloud_provider}")
    print(f"Security Score: {report.security_score:.1f}/100")
    print(f"Misconfigurations: {report.misconfigurations_found}")
    print(f"Critical: {report.critical_count}, High: {report.high_count}")
