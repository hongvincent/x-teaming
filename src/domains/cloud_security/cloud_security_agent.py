"""
Cloud Security Agent
Coordinates all cloud security modules
"""

from typing import Dict, Any, List

from .misconfiguration_detection import MisconfigurationDetectionModule
from .data_leakage_monitoring import DataLeakageMonitoringModule
from .container_security import ContainerSecurityModule
from .compliance_enforcement import ComplianceEnforcementModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class CloudSecurityAgent:
    """
    Cloud Security Agent
    Coordinates cloud security, compliance, and monitoring
    """

    def __init__(self):
        """Initialize Cloud Security Agent"""
        self.config = get_config()
        self.misconfig = MisconfigurationDetectionModule()
        self.dlp = DataLeakageMonitoringModule()
        self.container = ContainerSecurityModule()
        self.compliance = ComplianceEnforcementModule()
        logger.info("Cloud Security Agent initialized")

    def comprehensive_cloud_audit(self, cloud_config: Dict[str, Any], provider: str) -> Dict[str, Any]:
        """Comprehensive cloud security audit"""
        if provider.lower() == "aws":
            audit = self.misconfig.analyze_aws_config(cloud_config)
        elif provider.lower() == "kubernetes":
            audit = self.misconfig.analyze_kubernetes_config(cloud_config)
        else:
            audit = None

        return {
            "provider": provider,
            "security_score": audit.security_score if audit else 0,
            "misconfigurations": audit.misconfigurations_found if audit else 0,
            "critical_issues": audit.critical_count if audit else 0,
        }

    def get_agent_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_name": "Cloud Security Agent",
            "status": "active",
            "modules": {
                "misconfiguration_detection": "active",
                "data_leakage_monitoring": "active",
                "container_security": "active",
                "compliance_enforcement": "active",
            },
            "capabilities": [
                "Cloud misconfiguration detection (AWS, Azure, GCP, K8s)",
                "Data leakage monitoring and DLP",
                "Container security scanning",
                "Compliance validation (GDPR, SOC2, HIPAA, PCI-DSS)",
            ],
        }


if __name__ == "__main__":
    agent = CloudSecurityAgent()
    print(agent.get_agent_status())
