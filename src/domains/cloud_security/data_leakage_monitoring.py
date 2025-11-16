"""
Data Leakage Monitoring Module
Monitors and detects sensitive data exposure in cloud environments
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DataLeakageAlert:
    """Data leakage detection alert"""

    alert_id: str
    severity: str
    leak_type: str
    source: str
    destination: str
    data_classification: str
    sensitive_data_found: List[str]
    volume: str
    timestamp: str
    risk_score: float
    recommended_action: str


@dataclass
class SensitiveDataDiscovery:
    """Sensitive data discovery result"""

    location: str
    data_types_found: List[str]
    sample_count: int
    classification_level: str
    compliance_impact: List[str]
    encryption_status: bool
    access_controls: str


class DataLeakageMonitoringModule:
    """
    Data Leakage Monitoring Module
    Detects and prevents sensitive data exposure
    """

    def __init__(self):
        """Initialize data leakage monitoring module"""
        self.llm_client = LLMClient()
        logger.info("Data Leakage Monitoring Module initialized")

    def detect_data_leakage(self, traffic_log: Dict[str, Any]) -> DataLeakageAlert:
        """Detect data leakage in network traffic"""
        logger.info("Analyzing traffic for data leakage")

        system_message = """You are a data loss prevention (DLP) expert.
Detect sensitive data leakage:
- PII (SSN, credit cards, emails)
- Credentials and API keys
- Confidential business data
- Source code
- Database exports
- Compliance-protected data (GDPR, HIPAA)"""

        traffic_str = "\n".join([f"{k}: {v}" for k, v in traffic_log.items()])

        prompt = f"""Analyze this traffic for data leakage:

{traffic_str}

Provide analysis in JSON format:
{{
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "leak_type": "pii" | "credentials" | "source_code" | "database" | "confidential",
    "source": "source of leak",
    "destination": "destination",
    "data_classification": "public" | "internal" | "confidential" | "restricted",
    "sensitive_data_found": [types of sensitive data],
    "volume": "estimated data volume",
    "risk_score": float (0-100),
    "recommended_action": "immediate action required"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return DataLeakageAlert(
                alert_id=f"leak_{datetime.now().timestamp()}",
                severity=result.get("severity", "LOW"),
                leak_type=result.get("leak_type", "unknown"),
                source=result.get("source", ""),
                destination=result.get("destination", ""),
                data_classification=result.get("data_classification", "internal"),
                sensitive_data_found=result.get("sensitive_data_found", []),
                volume=result.get("volume", "unknown"),
                timestamp=datetime.now().isoformat(),
                risk_score=result.get("risk_score", 0.0),
                recommended_action=result.get("recommended_action", ""),
            )
        except Exception as e:
            logger.error(f"Data leakage detection failed: {e}")
            return DataLeakageAlert(
                alert_id="error",
                severity="UNKNOWN",
                leak_type="error",
                source="",
                destination="",
                data_classification="unknown",
                sensitive_data_found=[],
                volume="",
                timestamp=datetime.now().isoformat(),
                risk_score=0.0,
                recommended_action=f"Error: {e}",
            )

    def discover_sensitive_data(self, data_source: str, sample_data: str) -> SensitiveDataDiscovery:
        """Discover sensitive data in cloud storage"""
        logger.info(f"Discovering sensitive data in {data_source}")

        system_message = """You are a data classification expert.
Identify and classify sensitive data types:
- Personal information (names, addresses, SSN, DOB)
- Financial data (credit cards, bank accounts)
- Health information (medical records, diagnoses)
- Credentials (passwords, tokens, keys)
- Intellectual property"""

        prompt = f"""Analyze this data sample for sensitive information:

Data Source: {data_source}
Sample Data:
{sample_data[:1000]}

Provide discovery results in JSON format:
{{
    "data_types_found": [list of sensitive data types detected],
    "sample_count": estimated number of samples,
    "classification_level": "public" | "internal" | "confidential" | "restricted",
    "compliance_impact": ["GDPR", "HIPAA", "PCI-DSS", etc.],
    "encryption_status": boolean,
    "access_controls": "description of access controls"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return SensitiveDataDiscovery(
                location=data_source,
                data_types_found=result.get("data_types_found", []),
                sample_count=result.get("sample_count", 0),
                classification_level=result.get("classification_level", "internal"),
                compliance_impact=result.get("compliance_impact", []),
                encryption_status=result.get("encryption_status", False),
                access_controls=result.get("access_controls", ""),
            )
        except Exception as e:
            logger.error(f"Sensitive data discovery failed: {e}")
            return SensitiveDataDiscovery(
                location=data_source,
                data_types_found=[],
                sample_count=0,
                classification_level="unknown",
                compliance_impact=[],
                encryption_status=False,
                access_controls="",
            )


# Example usage
if __name__ == "__main__":
    monitor = DataLeakageMonitoringModule()

    traffic_log = {
        "source_ip": "10.0.0.5",
        "destination_ip": "203.0.113.50",
        "data_size": "500MB",
        "content_type": "application/json",
        "sample_content": '{"ssn":"123-45-6789","credit_card":"4532-1234-5678-9010"}',
    }

    print("=" * 70)
    print("DATA LEAKAGE DETECTION")
    print("=" * 70)

    alert = monitor.detect_data_leakage(traffic_log)
    print(f"Alert ID: {alert.alert_id}")
    print(f"Severity: {alert.severity}")
    print(f"Leak Type: {alert.leak_type}")
    print(f"Risk Score: {alert.risk_score:.1f}/100")
    print(f"Sensitive Data: {', '.join(alert.sensitive_data_found)}")
