"""
Incident Response Agent
Coordinates all incident response modules
"""

from typing import Dict, Any, List

from .alert_prioritization import AlertPrioritizationModule
from .threat_intelligence_analysis import ThreatIntelligenceAnalysisModule
from .threat_hunting import ThreatHuntingModule
from .malware_reverse_engineering import MalwareReverseEngineeringModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class IncidentResponseAgent:
    """
    Incident Response Agent
    Coordinates incident detection, analysis, and response
    """

    def __init__(self):
        """Initialize Incident Response Agent"""
        self.config = get_config()
        self.prioritization = AlertPrioritizationModule()
        self.threat_intel = ThreatIntelligenceAnalysisModule()
        self.hunting = ThreatHuntingModule()
        self.malware_analysis = MalwareReverseEngineeringModule()
        logger.info("Incident Response Agent initialized")

    def handle_incident(
        self, alerts: List[Dict[str, Any]], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Comprehensive incident handling"""
        # Prioritize alerts
        batch = self.prioritization.prioritize_alerts(alerts, context)

        # Generate threat intel
        incident_data = {"alerts": alerts, **context}
        threat_report = self.threat_intel.generate_threat_report(incident_data)

        return {
            "alert_triage": {
                "total": batch.total_alerts,
                "critical": batch.critical_count,
                "high": batch.high_count,
            },
            "threat_intelligence": {
                "threat_actor": threat_report.threat_actor,
                "severity": threat_report.severity,
                "iocs_found": len(threat_report.iocs),
            },
        }

    def get_agent_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_name": "Incident Response Agent",
            "status": "active",
            "modules": {
                "alert_prioritization": "active",
                "threat_intelligence": "active",
                "threat_hunting": "active",
                "malware_analysis": "active",
            },
            "capabilities": [
                "SIEM alert prioritization and triage",
                "IOC extraction and threat intelligence",
                "Proactive threat hunting",
                "Malware reverse engineering",
                "YARA rule generation",
            ],
        }


if __name__ == "__main__":
    agent = IncidentResponseAgent()
    print(agent.get_agent_status())
