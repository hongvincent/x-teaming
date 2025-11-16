"""
Behavioral Anomaly Detection Module
Detects anomalous behavior in IoT device traffic patterns
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BehaviorAnomaly:
    """IoT behavioral anomaly"""

    anomaly_id: str
    device_id: str
    device_type: str
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    indicators: List[str]
    baseline_deviation: str
    recommended_action: str
    timestamp: str


@dataclass
class IoTTrafficAnalysis:
    """IoT traffic analysis result"""

    analysis_id: str
    timestamp: str
    devices_analyzed: int
    anomalies_detected: int
    high_risk_devices: List[str]
    traffic_patterns: List[str]
    security_recommendations: List[str]


class BehavioralAnomalyDetectionModule:
    """
    Behavioral Anomaly Detection Module
    Detects anomalous behavior in IoT device traffic
    """

    def __init__(self):
        """Initialize behavioral anomaly detection module"""
        self.llm_client = LLMClient()
        logger.info("Behavioral Anomaly Detection Module initialized")

    def detect_iot_anomalies(
        self, device_traffic: Dict[str, Any], baseline: Dict[str, Any]
    ) -> BehaviorAnomaly:
        """
        Detect behavioral anomalies in IoT device

        Args:
            device_traffic: Current device traffic data
            baseline: Normal behavior baseline

        Returns:
            BehaviorAnomaly: Detected anomaly
        """
        logger.info(f"Analyzing IoT device: {device_traffic.get('device_id', 'unknown')}")

        system_message = """You are an IoT security analyst.
Detect anomalous IoT device behavior:
- Unusual traffic patterns
- Unexpected connections
- Command and control communication
- DDoS participation
- Data exfiltration
- Botnet activity
- Firmware tampering indicators"""

        traffic_str = "\n".join([f"{k}: {v}" for k, v in device_traffic.items()])
        baseline_str = "\n".join([f"{k}: {v}" for k, v in baseline.items()])

        prompt = f"""Analyze this IoT device traffic for anomalies:

Current Traffic:
{traffic_str}

Normal Baseline:
{baseline_str}

Provide anomaly analysis in JSON format:
{{
    "anomaly_type": "unusual_traffic" | "c2_communication" | "ddos" | "data_exfil" | "botnet" | "normal",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "confidence": float (0-1),
    "description": "detailed description",
    "indicators": [list of anomalous indicators],
    "baseline_deviation": "how it deviates from normal",
    "recommended_action": "immediate action needed"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return BehaviorAnomaly(
                anomaly_id=f"iot_anomaly_{datetime.now().timestamp()}",
                device_id=device_traffic.get("device_id", "unknown"),
                device_type=device_traffic.get("device_type", "unknown"),
                anomaly_type=result.get("anomaly_type", "normal"),
                severity=result.get("severity", "LOW"),
                confidence=result.get("confidence", 0.0),
                description=result.get("description", ""),
                indicators=result.get("indicators", []),
                baseline_deviation=result.get("baseline_deviation", ""),
                recommended_action=result.get("recommended_action", ""),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"IoT anomaly detection failed: {e}")
            return BehaviorAnomaly(
                anomaly_id="error",
                device_id="unknown",
                device_type="unknown",
                anomaly_type="error",
                severity="UNKNOWN",
                confidence=0.0,
                description=f"Detection error: {e}",
                indicators=[],
                baseline_deviation="",
                recommended_action="Manual investigation required",
                timestamp=datetime.now().isoformat(),
            )

    def analyze_iot_network(
        self, network_traffic: List[Dict[str, Any]]
    ) -> IoTTrafficAnalysis:
        """
        Analyze IoT network traffic patterns

        Args:
            network_traffic: Network traffic from multiple IoT devices

        Returns:
            IoTTrafficAnalysis: Network-wide analysis
        """
        logger.info(f"Analyzing IoT network with {len(network_traffic)} devices")

        system_message = """You are an IoT network security analyst.
Analyze IoT network for:
- Botnet command and control
- Lateral movement
- Compromised devices
- DDoS amplification
- Insecure protocols"""

        traffic_summary = "\n".join(
            [f"Device {i}: {traffic}" for i, traffic in enumerate(network_traffic[:10])]
        )

        prompt = f"""Analyze this IoT network traffic:

Network Traffic:
{traffic_summary}

Provide network analysis in JSON format:
{{
    "devices_analyzed": total device count,
    "anomalies_detected": anomaly count,
    "high_risk_devices": [list of high-risk device IDs],
    "traffic_patterns": [observed patterns],
    "security_recommendations": [network-wide recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return IoTTrafficAnalysis(
                analysis_id=f"network_analysis_{datetime.now().timestamp()}",
                timestamp=datetime.now().isoformat(),
                devices_analyzed=result.get("devices_analyzed", len(network_traffic)),
                anomalies_detected=result.get("anomalies_detected", 0),
                high_risk_devices=result.get("high_risk_devices", []),
                traffic_patterns=result.get("traffic_patterns", []),
                security_recommendations=result.get("security_recommendations", []),
            )

        except Exception as e:
            logger.error(f"IoT network analysis failed: {e}")
            return IoTTrafficAnalysis(
                analysis_id="error",
                timestamp=datetime.now().isoformat(),
                devices_analyzed=0,
                anomalies_detected=0,
                high_risk_devices=[],
                traffic_patterns=[],
                security_recommendations=[f"Analysis error: {e}"],
            )


# Example usage
if __name__ == "__main__":
    detector = BehavioralAnomalyDetectionModule()

    device_traffic = {
        "device_id": "camera-001",
        "device_type": "IP Camera",
        "outbound_connections": 500,
        "destinations": ["unknown-server.com:4444"],
        "data_volume": "10GB",
        "protocol": "TCP",
    }

    baseline = {
        "normal_connections": 10,
        "normal_destinations": ["cloud-service.com"],
        "normal_data_volume": "100MB",
    }

    print("=" * 70)
    print("IOT BEHAVIORAL ANOMALY DETECTION")
    print("=" * 70)

    anomaly = detector.detect_iot_anomalies(device_traffic, baseline)
    print(f"Device: {anomaly.device_id}")
    print(f"Anomaly Type: {anomaly.anomaly_type}")
    print(f"Severity: {anomaly.severity}")
    print(f"Confidence: {anomaly.confidence:.2f}")
    print(f"Action: {anomaly.recommended_action}")
