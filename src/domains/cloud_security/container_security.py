"""
Container Security Module
Scans Docker containers and images for vulnerabilities
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContainerVulnerability:
    """Container vulnerability finding"""

    vuln_id: str
    severity: str
    cve_id: str
    package: str
    version: str
    description: str
    remediation: str


@dataclass
class ContainerScanReport:
    """Container security scan report"""

    image_name: str
    scan_id: str
    timestamp: str
    vulnerabilities: List[ContainerVulnerability]
    security_score: float
    base_image_issues: List[str]
    configuration_issues: List[str]
    recommendations: List[str]


class ContainerSecurityModule:
    """
    Container Security Module
    Scans containers for vulnerabilities and misconfigurations
    """

    def __init__(self):
        """Initialize container security module"""
        self.llm_client = LLMClient()
        logger.info("Container Security Module initialized")

    def scan_docker_image(self, image_info: Dict[str, Any]) -> ContainerScanReport:
        """Scan Docker image for security issues"""
        logger.info(f"Scanning Docker image: {image_info.get('name', 'unknown')}")

        system_message = """You are a container security expert.
Identify vulnerabilities and issues:
- Vulnerable packages and CVEs
- Base image security
- Root user usage
- Exposed secrets
- Unnecessary packages
- Missing security updates"""

        image_str = "\n".join([f"{k}: {v}" for k, v in image_info.items()])

        prompt = f"""Scan this Docker image for security issues:

{image_str}

Provide scan results in JSON format:
{{
    "security_score": float (0-100),
    "vulnerabilities": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "cve_id": "CVE-XXXX-XXXXX",
            "package": "package name",
            "version": "vulnerable version",
            "description": "vulnerability description",
            "remediation": "how to fix"
        }}
    ],
    "base_image_issues": [list of base image problems],
    "configuration_issues": [list of config problems],
    "recommendations": [security recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            vulnerabilities = []
            for vuln in result.get("vulnerabilities", []):
                vulnerabilities.append(
                    ContainerVulnerability(
                        vuln_id=f"vuln_{len(vulnerabilities)}",
                        severity=vuln.get("severity", "MEDIUM"),
                        cve_id=vuln.get("cve_id", ""),
                        package=vuln.get("package", ""),
                        version=vuln.get("version", ""),
                        description=vuln.get("description", ""),
                        remediation=vuln.get("remediation", ""),
                    )
                )

            return ContainerScanReport(
                image_name=image_info.get("name", "unknown"),
                scan_id=f"scan_{datetime.now().timestamp()}",
                timestamp=datetime.now().isoformat(),
                vulnerabilities=vulnerabilities,
                security_score=result.get("security_score", 0.0),
                base_image_issues=result.get("base_image_issues", []),
                configuration_issues=result.get("configuration_issues", []),
                recommendations=result.get("recommendations", []),
            )
        except Exception as e:
            logger.error(f"Container scan failed: {e}")
            return ContainerScanReport(
                image_name=image_info.get("name", "error"),
                scan_id="error",
                timestamp=datetime.now().isoformat(),
                vulnerabilities=[],
                security_score=0.0,
                base_image_issues=[],
                configuration_issues=[],
                recommendations=[f"Scan error: {e}"],
            )


# Example usage
if __name__ == "__main__":
    scanner = ContainerSecurityModule()

    image_info = {
        "name": "myapp:latest",
        "base_image": "ubuntu:18.04",
        "user": "root",
        "packages": ["openssl==1.0.1", "python==3.6"],
    }

    report = scanner.scan_docker_image(image_info)
    print(f"Image: {report.image_name}")
    print(f"Security Score: {report.security_score:.1f}/100")
    print(f"Vulnerabilities: {len(report.vulnerabilities)}")
