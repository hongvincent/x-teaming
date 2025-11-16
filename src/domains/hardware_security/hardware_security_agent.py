"""
Hardware Security Agent
Coordinates all hardware security modules
"""

from typing import Dict, Any, List

from .hardware_vulnerability_detection import HardwareVulnerabilityDetectionModule
from .hardware_vulnerability_repair import HardwareVulnerabilityRepairModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class HardwareSecurityAgent:
    """
    Hardware Security Agent
    Coordinates hardware vulnerability detection and repair
    """

    def __init__(self):
        """Initialize Hardware Security Agent"""
        self.config = get_config()
        self.detection = HardwareVulnerabilityDetectionModule()
        self.repair = HardwareVulnerabilityRepairModule()
        logger.info("Hardware Security Agent initialized")

    def comprehensive_hardware_audit(self, hdl_code: str, design_name: str) -> Dict[str, Any]:
        """Comprehensive hardware security audit"""
        audit = self.detection.analyze_hdl_code(hdl_code, design_name)
        trojan = self.detection.detect_hardware_trojans(hdl_code)
        side_channel = self.detection.analyze_side_channels(hdl_code)

        return {
            "audit": {
                "security_score": audit.security_score,
                "vulnerabilities": len(audit.vulnerabilities),
                "overall_risk": audit.overall_risk,
            },
            "trojan_detection": {
                "detected": trojan.get("trojan_detected", False),
                "confidence": trojan.get("confidence", 0.0),
            },
            "side_channel": {
                "vulnerable": side_channel.get("vulnerable_to_side_channels", False),
                "timing_leakage": side_channel.get("timing_leakage", False),
                "power_leakage": side_channel.get("power_leakage", False),
            },
        }

    def get_agent_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_name": "Hardware Security Agent",
            "status": "active",
            "modules": {
                "vulnerability_detection": "active",
                "vulnerability_repair": "active",
            },
            "capabilities": [
                "HDL/Verilog security analysis",
                "Hardware Trojan detection",
                "Side-channel vulnerability detection",
                "Security assertion generation",
                "Vulnerability patching",
            ],
        }


if __name__ == "__main__":
    agent = HardwareSecurityAgent()
    print(agent.get_agent_status())
