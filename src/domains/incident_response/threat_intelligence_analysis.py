"""
Threat Intelligence Analysis Module
Extracts IOCs and generates cyber threat intelligence
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class IOC:
    """Indicator of Compromise"""

    ioc_type: str  # ip, domain, hash, email, url
    value: str
    confidence: float
    context: str
    first_seen: str
    threat_type: str


@dataclass
class ThreatIntelReport:
    """Threat intelligence report"""

    report_id: str
    timestamp: str
    threat_actor: str
    campaign_name: str
    ttps: List[str]  # MITRE ATT&CK TTPs
    iocs: List[IOC]
    severity: str
    target_sectors: List[str]
    recommendations: List[str]
    executive_summary: str


class ThreatIntelligenceAnalysisModule:
    """
    Threat Intelligence Analysis Module
    Extracts IOCs and generates CTI reports
    """

    def __init__(self):
        """Initialize threat intelligence module"""
        self.llm_client = LLMClient()
        logger.info("Threat Intelligence Analysis Module initialized")

    def extract_iocs(self, text: str) -> List[IOC]:
        """Extract indicators of compromise from text"""
        logger.info("Extracting IOCs from text")

        system_message = """You are a cyber threat intelligence analyst.
Extract indicators of compromise (IOCs):
- IP addresses
- Domain names
- File hashes (MD5, SHA256)
- Email addresses
- URLs
- Registry keys
- Filenames"""

        prompt = f"""Extract all IOCs from this text:

{text[:2500]}

Provide IOCs in JSON format:
{{
    "iocs": [
        {{
            "ioc_type": "ip" | "domain" | "hash" | "email" | "url" | "file",
            "value": "IOC value",
            "confidence": float (0-1),
            "context": "context where found",
            "threat_type": "malware" | "c2" | "phishing" | "exploit"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            iocs = []
            for ioc in result.get("iocs", []):
                iocs.append(
                    IOC(
                        ioc_type=ioc.get("ioc_type", "unknown"),
                        value=ioc.get("value", ""),
                        confidence=ioc.get("confidence", 0.5),
                        context=ioc.get("context", ""),
                        first_seen=datetime.now().isoformat(),
                        threat_type=ioc.get("threat_type", "unknown"),
                    )
                )

            logger.info(f"Extracted {len(iocs)} IOCs")
            return iocs

        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            return []

    def generate_threat_report(self, incident_data: Dict[str, Any]) -> ThreatIntelReport:
        """Generate cyber threat intelligence report"""
        logger.info("Generating threat intelligence report")

        system_message = """You are a threat intelligence analyst.
Generate comprehensive CTI reports with:
- Threat actor attribution
- Campaign identification
- MITRE ATT&CK mapping
- IOCs
- Recommendations"""

        incident_str = "\n".join([f"{k}: {v}" for k, v in incident_data.items()])

        prompt = f"""Generate a threat intelligence report for this incident:

Incident Data:
{incident_str}

Provide CTI report in JSON format:
{{
    "threat_actor": "threat actor name or APT designation",
    "campaign_name": "campaign or operation name",
    "ttps": ["T1566.001", "T1059.001"],
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "target_sectors": [targeted industries/sectors],
    "recommendations": [tactical recommendations],
    "executive_summary": "2-3 sentence summary"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            # Extract IOCs from incident data
            incident_text = str(incident_data)
            iocs = self.extract_iocs(incident_text)

            return ThreatIntelReport(
                report_id=f"cti_{datetime.now().timestamp()}",
                timestamp=datetime.now().isoformat(),
                threat_actor=result.get("threat_actor", "Unknown"),
                campaign_name=result.get("campaign_name", "Unidentified"),
                ttps=result.get("ttps", []),
                iocs=iocs,
                severity=result.get("severity", "MEDIUM"),
                target_sectors=result.get("target_sectors", []),
                recommendations=result.get("recommendations", []),
                executive_summary=result.get("executive_summary", ""),
            )

        except Exception as e:
            logger.error(f"Threat report generation failed: {e}")
            return ThreatIntelReport(
                report_id="error",
                timestamp=datetime.now().isoformat(),
                threat_actor="Unknown",
                campaign_name="Unknown",
                ttps=[],
                iocs=[],
                severity="UNKNOWN",
                target_sectors=[],
                recommendations=[f"Report generation error: {e}"],
                executive_summary="",
            )


# Example usage
if __name__ == "__main__":
    intel = ThreatIntelligenceAnalysisModule()

    text = """
    Observed malicious activity from IP 203.0.113.50 connecting to C2 domain evil-c2.com.
    File hash SHA256: a3b4c5d6e7f8... identified as TrickBot malware.
    Phishing emails from attacker@malicious.net targeting finance department.
    """

    print("=" * 70)
    print("IOC EXTRACTION")
    print("=" * 70)

    iocs = intel.extract_iocs(text)
    for ioc in iocs:
        print(f"{ioc.ioc_type}: {ioc.value} (confidence: {ioc.confidence:.2f})")
