"""
Traffic & Intrusion Detection Module
Analyzes network traffic for anomalies and malicious patterns
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import pandas as pd
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AnomalyReport:
    """Network anomaly report"""

    timestamp: str
    anomaly_detected: bool
    anomaly_type: str
    confidence: float
    affected_ips: List[str]
    indicators: List[str]
    severity: str
    description: str
    recommendations: List[str]


@dataclass
class URLClassification:
    """URL classification result"""

    url: str
    is_malicious: bool
    confidence: float
    threat_types: List[str]
    indicators: List[str]
    explanation: str


@dataclass
class AttackPattern:
    """Detected attack pattern"""

    pattern_name: str
    attack_type: str
    technique_id: str  # MITRE ATT&CK ID
    description: str
    severity: str
    occurrences: int


class TrafficDetectionModule:
    """
    Network Traffic & Intrusion Detection Module
    Uses LLM for intelligent traffic analysis and threat detection
    """

    def __init__(self):
        """Initialize traffic detection module"""
        self.llm_client = LLMClient()
        logger.info("Traffic Detection Module initialized")

    def analyze_network_flow(
        self, traffic_data: Dict[str, Any], context: Optional[str] = None
    ) -> AnomalyReport:
        """
        Analyze network traffic flow for anomalies

        Args:
            traffic_data: Network traffic data (IPs, ports, protocols, etc.)
            context: Additional context about the network

        Returns:
            AnomalyReport: Analysis results
        """
        logger.info("Analyzing network traffic flow")

        system_message = """You are a network security expert specializing in intrusion detection.
Analyze network traffic patterns to identify anomalies, suspicious behavior, and potential attacks.
Consider traffic volume, protocols, port usage, and connection patterns."""

        # Format traffic data
        traffic_str = self._format_traffic_data(traffic_data)

        prompt = f"""Analyze this network traffic for anomalies and threats:

{traffic_str}

{f'Network Context: {context}' if context else ''}

Provide detailed analysis in JSON format:
{{
    "anomaly_detected": boolean,
    "anomaly_type": "port_scan" | "ddos" | "data_exfiltration" | "lateral_movement" | "none",
    "confidence": float (0-1),
    "affected_ips": [list of suspicious IPs],
    "indicators": [list of suspicious indicators],
    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "description": "detailed description",
    "recommendations": [list of recommended actions]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return AnomalyReport(
                timestamp=datetime.now().isoformat(),
                anomaly_detected=result.get("anomaly_detected", False),
                anomaly_type=result.get("anomaly_type", "none"),
                confidence=result.get("confidence", 0.0),
                affected_ips=result.get("affected_ips", []),
                indicators=result.get("indicators", []),
                severity=result.get("severity", "LOW"),
                description=result.get("description", ""),
                recommendations=result.get("recommendations", []),
            )

        except Exception as e:
            logger.error(f"Network flow analysis failed: {e}")
            return AnomalyReport(
                timestamp=datetime.now().isoformat(),
                anomaly_detected=False,
                anomaly_type="error",
                confidence=0.0,
                affected_ips=[],
                indicators=[],
                severity="UNKNOWN",
                description=f"Analysis error: {e}",
                recommendations=["Review traffic data manually"],
            )

    def detect_malicious_urls(self, urls: List[str]) -> List[URLClassification]:
        """
        Detect malicious URLs

        Args:
            urls: List of URLs to analyze

        Returns:
            List[URLClassification]: Classification results for each URL
        """
        logger.info(f"Analyzing {len(urls)} URLs for threats")

        system_message = """You are a cybersecurity expert specializing in URL threat analysis.
Identify malicious URLs based on domain reputation, URL patterns, and suspicious indicators.
Consider phishing, malware distribution, C2 servers, and other threats."""

        # Analyze URLs in batches
        results = []

        for url in urls:
            prompt = f"""Analyze this URL for security threats:

URL: {url}

Provide analysis in JSON format:
{{
    "is_malicious": boolean,
    "confidence": float (0-1),
    "threat_types": [list of threat types: "phishing", "malware", "c2", "scam", etc.],
    "indicators": [list of suspicious indicators found],
    "explanation": "detailed explanation"
}}"""

            try:
                result = self.llm_client.complete_with_json(
                    prompt, system_message=system_message
                )

                classification = URLClassification(
                    url=url,
                    is_malicious=result.get("is_malicious", False),
                    confidence=result.get("confidence", 0.0),
                    threat_types=result.get("threat_types", []),
                    indicators=result.get("indicators", []),
                    explanation=result.get("explanation", ""),
                )
                results.append(classification)

            except Exception as e:
                logger.error(f"URL analysis failed for {url}: {e}")
                results.append(
                    URLClassification(
                        url=url,
                        is_malicious=False,
                        confidence=0.0,
                        threat_types=[],
                        indicators=[],
                        explanation=f"Analysis error: {e}",
                    )
                )

        logger.info(
            f"Detected {sum(1 for r in results if r.is_malicious)} malicious URLs"
        )
        return results

    def identify_attack_patterns(
        self, traffic_log: pd.DataFrame
    ) -> List[AttackPattern]:
        """
        Identify attack patterns in traffic logs

        Args:
            traffic_log: DataFrame with traffic logs

        Returns:
            List[AttackPattern]: Detected attack patterns
        """
        logger.info(f"Analyzing {len(traffic_log)} log entries for attack patterns")

        # Prepare log summary
        log_summary = self._summarize_traffic_log(traffic_log)

        system_message = """You are a threat intelligence expert specializing in attack pattern recognition.
Map network behaviors to MITRE ATT&CK techniques and identify attack campaigns.
Focus on reconnaissance, lateral movement, command and control, and exfiltration patterns."""

        prompt = f"""Analyze this network traffic summary for attack patterns:

{log_summary}

Identify attack patterns and map to MITRE ATT&CK techniques.

Respond in JSON format:
{{
    "patterns": [
        {{
            "pattern_name": "name of the attack pattern",
            "attack_type": "reconnaissance|initial_access|lateral_movement|exfiltration|c2",
            "technique_id": "MITRE ATT&CK technique ID (e.g., T1046)",
            "description": "detailed description",
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "occurrences": number of times detected
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            patterns = []
            for pattern_data in result.get("patterns", []):
                pattern = AttackPattern(
                    pattern_name=pattern_data.get("pattern_name", "Unknown"),
                    attack_type=pattern_data.get("attack_type", "unknown"),
                    technique_id=pattern_data.get("technique_id", ""),
                    description=pattern_data.get("description", ""),
                    severity=pattern_data.get("severity", "MEDIUM"),
                    occurrences=pattern_data.get("occurrences", 1),
                )
                patterns.append(pattern)

            logger.info(f"Identified {len(patterns)} attack patterns")
            return patterns

        except Exception as e:
            logger.error(f"Attack pattern identification failed: {e}")
            return []

    def detect_zero_day_attacks(
        self, traffic_data: Dict[str, Any], historical_baseline: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Detect potential zero-day attacks using anomaly detection

        Args:
            traffic_data: Current traffic data
            historical_baseline: Historical normal behavior baseline

        Returns:
            Dict: Zero-day attack detection results
        """
        logger.info("Analyzing for potential zero-day attacks")

        system_message = """You are an advanced threat detection expert specializing in zero-day attacks.
Identify unusual patterns that don't match known attack signatures.
Look for novel techniques, unusual protocol usage, and abnormal behavior patterns."""

        traffic_str = self._format_traffic_data(traffic_data)
        baseline_str = (
            self._format_traffic_data(historical_baseline)
            if historical_baseline
            else "No baseline available"
        )

        prompt = f"""Analyze this traffic for potential zero-day attacks by comparing with normal baseline:

Current Traffic:
{traffic_str}

Historical Baseline:
{baseline_str}

Look for:
1. Novel attack techniques
2. Unusual protocol combinations
3. Abnormal data patterns
4. Unexpected port usage
5. Suspicious timing patterns

Respond in JSON format:
{{
    "zero_day_detected": boolean,
    "confidence": float (0-1),
    "novel_indicators": [list of unusual indicators],
    "behavioral_anomalies": [list of anomalies],
    "potential_impact": "description",
    "recommended_actions": [list of actions]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "zero_day_detected": result.get("zero_day_detected", False),
                "confidence": result.get("confidence", 0.0),
                "novel_indicators": result.get("novel_indicators", []),
                "behavioral_anomalies": result.get("behavioral_anomalies", []),
                "potential_impact": result.get("potential_impact", ""),
                "recommended_actions": result.get("recommended_actions", []),
            }

        except Exception as e:
            logger.error(f"Zero-day detection failed: {e}")
            return {"error": str(e), "zero_day_detected": False}

    def _format_traffic_data(self, traffic_data: Dict[str, Any]) -> str:
        """Format traffic data for LLM analysis"""
        if isinstance(traffic_data, pd.DataFrame):
            return traffic_data.head(10).to_string()

        formatted = []
        for key, value in traffic_data.items():
            formatted.append(f"{key}: {value}")
        return "\n".join(formatted)

    def _summarize_traffic_log(self, traffic_log: pd.DataFrame) -> str:
        """Summarize traffic log for analysis"""
        summary_parts = [
            f"Total entries: {len(traffic_log)}",
            f"Unique source IPs: {traffic_log['src_ip'].nunique() if 'src_ip' in traffic_log.columns else 'N/A'}",
            f"Unique destination IPs: {traffic_log['dst_ip'].nunique() if 'dst_ip' in traffic_log.columns else 'N/A'}",
            f"Protocols: {traffic_log['protocol'].value_counts().to_dict() if 'protocol' in traffic_log.columns else 'N/A'}",
            f"Top ports: {traffic_log['port'].value_counts().head(5).to_dict() if 'port' in traffic_log.columns else 'N/A'}",
        ]

        # Add sample entries
        if len(traffic_log) > 0:
            summary_parts.append("\nSample entries:")
            summary_parts.append(traffic_log.head(5).to_string())

        return "\n".join(summary_parts)


# Example usage
if __name__ == "__main__":
    detector = TrafficDetectionModule()

    # Test network flow analysis
    print("=" * 50)
    print("Network Flow Analysis")
    print("=" * 50)

    traffic_data = {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "protocol": "TCP",
        "dst_port": 443,
        "bytes_sent": 15000,
        "bytes_received": 250000,
        "duration": 300,
        "flags": "SYN, ACK",
    }

    report = detector.analyze_network_flow(
        traffic_data, context="Corporate network, HTTPS traffic"
    )
    print(f"Anomaly Detected: {report.anomaly_detected}")
    print(f"Type: {report.anomaly_type}")
    print(f"Severity: {report.severity}")
    print(f"Description: {report.description}")

    # Test URL detection
    print("\n" + "=" * 50)
    print("Malicious URL Detection")
    print("=" * 50)

    test_urls = [
        "https://google.com",
        "http://evil-phishing-site.ru/login",
        "https://github.com/user/repo",
    ]

    url_results = detector.detect_malicious_urls(test_urls)
    for result in url_results:
        print(f"\nURL: {result.url}")
        print(f"Malicious: {result.is_malicious}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Threat Types: {', '.join(result.threat_types)}")

    # Test attack pattern identification
    print("\n" + "=" * 50)
    print("Attack Pattern Identification")
    print("=" * 50)

    # Create sample traffic log
    traffic_log = pd.DataFrame(
        {
            "timestamp": ["2025-01-01 10:00:00"] * 5,
            "src_ip": ["10.0.0.50"] * 5,
            "dst_ip": [f"192.168.1.{i}" for i in range(1, 6)],
            "protocol": ["TCP"] * 5,
            "port": [22, 23, 445, 3389, 5900],
            "flags": ["SYN"] * 5,
        }
    )

    patterns = detector.identify_attack_patterns(traffic_log)
    for pattern in patterns:
        print(f"\nPattern: {pattern.pattern_name}")
        print(f"Type: {pattern.attack_type}")
        print(f"MITRE ATT&CK: {pattern.technique_id}")
        print(f"Severity: {pattern.severity}")
