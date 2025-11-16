"""
Alert Prioritization Module
Ranks and prioritizes security alerts from SIEM systems
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PrioritizedAlert:
    """Prioritized security alert"""

    alert_id: str
    original_severity: str
    adjusted_severity: str
    priority_score: float
    category: str
    source: str
    indicators: List[str]
    business_impact: str
    recommended_action: str
    escalation_needed: bool
    timestamp: str


@dataclass
class AlertBatch:
    """Batch of prioritized alerts"""

    batch_id: str
    timestamp: str
    total_alerts: int
    critical_count: int
    high_count: int
    prioritized_alerts: List[PrioritizedAlert]
    triage_recommendations: List[str]


class AlertPrioritizationModule:
    """
    Alert Prioritization Module
    Intelligently ranks and prioritizes SIEM alerts
    """

    def __init__(self):
        """Initialize alert prioritization module"""
        self.llm_client = LLMClient()
        logger.info("Alert Prioritization Module initialized")

    def prioritize_alerts(
        self, alerts: List[Dict[str, Any]], context: Dict[str, Any]
    ) -> AlertBatch:
        """
        Prioritize batch of security alerts

        Args:
            alerts: List of security alerts
            context: Organizational context (assets, business criticality)

        Returns:
            AlertBatch: Prioritized alerts with recommendations
        """
        logger.info(f"Prioritizing {len(alerts)} security alerts")

        system_message = """You are a security operations expert specializing in alert triage.
Prioritize alerts based on:
- True threat vs false positive likelihood
- Potential business impact
- Attack progression stage
- Asset criticality
- Threat actor sophistication
- Lateral movement indicators
- Data exfiltration risks"""

        alerts_str = "\n".join([f"Alert {i+1}: {alert}" for i, alert in enumerate(alerts[:10])])
        context_str = "\n".join([f"{k}: {v}" for k, v in context.items()])

        prompt = f"""Prioritize these security alerts:

Context:
{context_str}

Alerts:
{alerts_str}

Provide prioritization in JSON format:
{{
    "prioritized_alerts": [
        {{
            "alert_id": "original alert ID",
            "original_severity": "original severity",
            "adjusted_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
            "priority_score": float (0-100),
            "category": "malware" | "intrusion" | "data_theft" | "false_positive",
            "indicators": [key indicators],
            "business_impact": "potential business impact",
            "recommended_action": "immediate action needed",
            "escalation_needed": boolean
        }}
    ],
    "triage_recommendations": [overall triage recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            prioritized = []
            for alert in result.get("prioritized_alerts", []):
                prioritized.append(
                    PrioritizedAlert(
                        alert_id=alert.get("alert_id", f"alert_{len(prioritized)}"),
                        original_severity=alert.get("original_severity", "MEDIUM"),
                        adjusted_severity=alert.get("adjusted_severity", "MEDIUM"),
                        priority_score=alert.get("priority_score", 50.0),
                        category=alert.get("category", "unknown"),
                        source=alerts[len(prioritized)].get("source", "unknown")
                        if len(prioritized) < len(alerts)
                        else "unknown",
                        indicators=alert.get("indicators", []),
                        business_impact=alert.get("business_impact", ""),
                        recommended_action=alert.get("recommended_action", ""),
                        escalation_needed=alert.get("escalation_needed", False),
                        timestamp=datetime.now().isoformat(),
                    )
                )

            # Sort by priority score
            prioritized.sort(key=lambda x: x.priority_score, reverse=True)

            critical_count = sum(1 for a in prioritized if a.adjusted_severity == "CRITICAL")
            high_count = sum(1 for a in prioritized if a.adjusted_severity == "HIGH")

            return AlertBatch(
                batch_id=f"batch_{datetime.now().timestamp()}",
                timestamp=datetime.now().isoformat(),
                total_alerts=len(prioritized),
                critical_count=critical_count,
                high_count=high_count,
                prioritized_alerts=prioritized,
                triage_recommendations=result.get("triage_recommendations", []),
            )

        except Exception as e:
            logger.error(f"Alert prioritization failed: {e}")
            return AlertBatch(
                batch_id="error",
                timestamp=datetime.now().isoformat(),
                total_alerts=0,
                critical_count=0,
                high_count=0,
                prioritized_alerts=[],
                triage_recommendations=[f"Prioritization error: {e}"],
            )


# Example usage
if __name__ == "__main__":
    prioritizer = AlertPrioritizationModule()

    alerts = [
        {
            "id": "alert_001",
            "severity": "HIGH",
            "type": "malware_detected",
            "source": "endpoint",
            "description": "Suspicious process execution on finance workstation",
        },
        {
            "id": "alert_002",
            "severity": "MEDIUM",
            "type": "failed_login",
            "source": "vpn",
            "description": "Multiple failed login attempts",
        },
        {
            "id": "alert_003",
            "severity": "HIGH",
            "type": "data_exfil",
            "source": "network",
            "description": "Large data transfer to unknown IP",
        },
    ]

    context = {
        "organization": "Financial Services Company",
        "critical_assets": ["customer_database", "trading_platform"],
        "business_hours": "9-5 EST",
    }

    batch = prioritizer.prioritize_alerts(alerts, context)
    print(f"Batch ID: {batch.batch_id}")
    print(f"Total Alerts: {batch.total_alerts}")
    print(f"Critical: {batch.critical_count}, High: {batch.high_count}")

    for alert in batch.prioritized_alerts[:3]:
        print(f"\n{alert.alert_id} - Priority: {alert.priority_score:.1f}")
        print(f"  Severity: {alert.adjusted_severity}")
        print(f"  Action: {alert.recommended_action[:80]}...")
