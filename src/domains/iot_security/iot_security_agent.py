"""
IoT Security Agent
Coordinates all IoT security modules
"""

from typing import Dict, Any, List

from .firmware_vulnerability_detection import FirmwareVulnerabilityDetectionModule
from .behavioral_anomaly_detection import BehavioralAnomalyDetectionModule
from .threat_report_summarization import ThreatReportSummarizationModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class IoTSecurityAgent:
    """
    IoT Security Agent
    Coordinates IoT security analysis, monitoring, and reporting
    """

    def __init__(self):
        """Initialize IoT Security Agent"""
        self.config = get_config()
        self.firmware_scanner = FirmwareVulnerabilityDetectionModule()
        self.behavior_monitor = BehavioralAnomalyDetectionModule()
        self.report_summarizer = ThreatReportSummarizationModule()
        logger.info("IoT Security Agent initialized")

    def comprehensive_iot_assessment(
        self, firmware_info: Dict[str, Any], network_traffic: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Comprehensive IoT security assessment"""
        # Firmware analysis
        firmware_report = self.firmware_scanner.analyze_firmware(firmware_info, {})

        # Network behavior analysis
        network_analysis = self.behavior_monitor.analyze_iot_network(network_traffic)

        return {
            "firmware_security": {
                "score": firmware_report.security_score,
                "vulnerabilities": len(firmware_report.vulnerabilities),
                "hardcoded_credentials": len(firmware_report.hardcoded_credentials),
                "backdoors": firmware_report.backdoors_detected,
            },
            "network_behavior": {
                "devices_analyzed": network_analysis.devices_analyzed,
                "anomalies_detected": network_analysis.anomalies_detected,
                "high_risk_devices": len(network_analysis.high_risk_devices),
            },
        }

    def get_agent_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_name": "IoT Security Agent",
            "status": "active",
            "modules": {
                "firmware_vulnerability_detection": "active",
                "behavioral_anomaly_detection": "active",
                "threat_report_summarization": "active",
            },
            "capabilities": [
                "IoT firmware vulnerability analysis",
                "Behavioral anomaly detection",
                "IoT network traffic monitoring",
                "Automated threat report summarization",
                "Executive briefing generation",
            ],
        }


# Example usage
if __name__ == "__main__":
    agent = IoTSecurityAgent()

    print("=" * 70)
    print("IOT SECURITY AGENT STATUS")
    print("=" * 70)
    status = agent.get_agent_status()
    print(f"Agent: {status['agent_name']}")
    print(f"Status: {status['status']}")
    print("\nCapabilities:")
    for capability in status["capabilities"]:
        print(f"  - {capability}")
