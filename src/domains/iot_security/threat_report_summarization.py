"""
Threat Report Summarization Module
Automatically summarizes security threat reports
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ThreatReportSummary:
    """Threat report summary"""

    report_id: str
    title: str
    executive_summary: str
    key_findings: List[str]
    threat_level: str
    affected_systems: List[str]
    iocs: List[str]
    recommendations: List[str]
    timeline: List[str]
    technical_details: str
    timestamp: str


class ThreatReportSummarizationModule:
    """
    Threat Report Summarization Module
    Automatically summarizes and extracts key information from threat reports
    """

    def __init__(self):
        """Initialize threat report summarization module"""
        self.llm_client = LLMClient()
        logger.info("Threat Report Summarization Module initialized")

    def summarize_threat_report(
        self, report_text: str, report_title: str = "Security Incident"
    ) -> ThreatReportSummary:
        """
        Summarize threat report

        Args:
            report_text: Full threat report text
            report_title: Report title

        Returns:
            ThreatReportSummary: Summarized report
        """
        logger.info(f"Summarizing threat report: {report_title}")

        system_message = """You are a security analyst expert at summarizing threat reports.
Create concise, actionable summaries that highlight:
- Executive summary (2-3 sentences)
- Key findings
- Threat level assessment
- Affected systems
- IOCs
- Actionable recommendations
- Timeline of events"""

        prompt = f"""Summarize this security threat report:

Title: {report_title}

Report:
{report_text[:3000]}

Provide summary in JSON format:
{{
    "executive_summary": "2-3 sentence high-level summary",
    "key_findings": [list of 3-5 most important findings],
    "threat_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "affected_systems": [list of affected systems/devices],
    "iocs": [extracted indicators of compromise],
    "recommendations": [top 3-5 actionable recommendations],
    "timeline": [chronological key events],
    "technical_details": "brief technical summary"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return ThreatReportSummary(
                report_id=f"summary_{datetime.now().timestamp()}",
                title=report_title,
                executive_summary=result.get("executive_summary", ""),
                key_findings=result.get("key_findings", []),
                threat_level=result.get("threat_level", "MEDIUM"),
                affected_systems=result.get("affected_systems", []),
                iocs=result.get("iocs", []),
                recommendations=result.get("recommendations", []),
                timeline=result.get("timeline", []),
                technical_details=result.get("technical_details", ""),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Report summarization failed: {e}")
            return ThreatReportSummary(
                report_id="error",
                title=report_title,
                executive_summary=f"Summarization error: {e}",
                key_findings=[],
                threat_level="UNKNOWN",
                affected_systems=[],
                iocs=[],
                recommendations=[],
                timeline=[],
                technical_details="",
                timestamp=datetime.now().isoformat(),
            )

    def generate_executive_brief(
        self, incident_data: Dict[str, Any]
    ) -> str:
        """
        Generate executive brief from incident data

        Args:
            incident_data: Incident information

        Returns:
            str: Executive brief text
        """
        logger.info("Generating executive brief")

        system_message = """You are a security communications expert.
Create executive briefs for non-technical leadership that:
- Use clear, non-technical language
- Focus on business impact
- Provide actionable next steps
- Keep it concise (1 page max)"""

        incident_str = "\n".join([f"{k}: {v}" for k, v in incident_data.items()])

        prompt = f"""Generate an executive brief for this security incident:

Incident Data:
{incident_str}

Provide brief in JSON format:
{{
    "executive_brief": "complete executive brief text (non-technical)"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            return result.get("executive_brief", "Brief generation failed")

        except Exception as e:
            logger.error(f"Executive brief generation failed: {e}")
            return f"Error generating brief: {e}"


# Example usage
if __name__ == "__main__":
    summarizer = ThreatReportSummarizationModule()

    threat_report = """
    On January 15, 2025, our security team detected unusual network traffic from
    multiple IoT devices including IP cameras and smart sensors. Investigation
    revealed that these devices were compromised and participating in a botnet.

    The attackers exploited CVE-2024-12345, a hardcoded credential vulnerability
    in firmware version 1.2.3. Compromised devices were communicating with C2
    server at 203.0.113.50 on port 4444.

    The botnet was used to launch DDoS attacks against external targets. We
    immediately isolated affected devices, blocked C2 communication, and began
    firmware updates. No customer data was compromised.

    Recommendations: 1) Update all IoT firmware, 2) Segment IoT network,
    3) Implement network monitoring, 4) Disable unused services.
    """

    print("=" * 70)
    print("THREAT REPORT SUMMARIZATION")
    print("=" * 70)

    summary = summarizer.summarize_threat_report(threat_report, "IoT Botnet Incident")
    print(f"Title: {summary.title}")
    print(f"Threat Level: {summary.threat_level}")
    print(f"\nExecutive Summary:")
    print(summary.executive_summary)
    print(f"\nKey Findings:")
    for finding in summary.key_findings:
        print(f"  - {finding}")
    print(f"\nRecommendations:")
    for rec in summary.recommendations[:3]:
        print(f"  - {rec}")
