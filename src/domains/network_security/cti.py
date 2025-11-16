"""
Cyber Threat Intelligence (CTI) Module
Generates and analyzes threat intelligence reports
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class IOC:
    """Indicator of Compromise"""

    type: str  # ip, domain, hash, url, email
    value: str
    description: str
    severity: str
    first_seen: str
    last_seen: str
    tags: List[str]


@dataclass
class CTIReport:
    """Cyber Threat Intelligence Report"""

    report_id: str
    title: str
    timestamp: str
    threat_actor: str
    ttps: List[str]  # Tactics, Techniques, Procedures
    iocs: List[IOC]
    affected_sectors: List[str]
    severity: str
    executive_summary: str
    technical_details: str
    recommendations: List[str]


@dataclass
class ThreatActorProfile:
    """Threat Actor Profile"""

    name: str
    aliases: List[str]
    origin: str
    motivation: str
    sophistication: str
    target_sectors: List[str]
    known_ttps: List[str]
    associated_campaigns: List[str]
    description: str


class CTIModule:
    """
    Cyber Threat Intelligence Module
    Generates threat intelligence and extracts IOCs
    """

    def __init__(self):
        """Initialize CTI module"""
        self.llm_client = LLMClient()
        logger.info("CTI Module initialized")

    def generate_threat_report(
        self,
        incident_data: Dict[str, Any],
        data_sources: Optional[List[str]] = None,
    ) -> CTIReport:
        """
        Generate comprehensive threat intelligence report

        Args:
            incident_data: Security incident data
            data_sources: Additional threat intelligence sources

        Returns:
            CTIReport: Generated threat intelligence report
        """
        logger.info("Generating threat intelligence report")

        system_message = """You are a senior threat intelligence analyst.
Generate comprehensive, actionable threat intelligence reports based on security incidents.
Include IOCs, TTPs mapped to MITRE ATT&CK, and strategic recommendations."""

        # Format incident data
        incident_str = "\n".join([f"{k}: {v}" for k, v in incident_data.items()])
        sources_str = (
            "\n".join(data_sources) if data_sources else "Internal incident data only"
        )

        prompt = f"""Generate a comprehensive threat intelligence report based on this incident:

Incident Data:
{incident_str}

Additional Sources:
{sources_str}

Provide a complete CTI report in JSON format:
{{
    "title": "report title",
    "threat_actor": "identified or suspected threat actor",
    "ttps": ["list of TTPs with MITRE ATT&CK IDs"],
    "iocs": [
        {{
            "type": "ip|domain|hash|url|email",
            "value": "IOC value",
            "description": "what this IOC indicates",
            "severity": "LOW|MEDIUM|HIGH|CRITICAL"
        }}
    ],
    "affected_sectors": ["list of affected industry sectors"],
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "executive_summary": "high-level summary for leadership",
    "technical_details": "detailed technical analysis",
    "recommendations": ["list of actionable recommendations"]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message, max_tokens=2000
            )

            # Parse IOCs
            iocs = []
            for ioc_data in result.get("iocs", []):
                ioc = IOC(
                    type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    description=ioc_data.get("description", ""),
                    severity=ioc_data.get("severity", "MEDIUM"),
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=[],
                )
                iocs.append(ioc)

            report = CTIReport(
                report_id=f"CTI-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                title=result.get("title", "Threat Intelligence Report"),
                timestamp=datetime.now().isoformat(),
                threat_actor=result.get("threat_actor", "Unknown"),
                ttps=result.get("ttps", []),
                iocs=iocs,
                affected_sectors=result.get("affected_sectors", []),
                severity=result.get("severity", "MEDIUM"),
                executive_summary=result.get("executive_summary", ""),
                technical_details=result.get("technical_details", ""),
                recommendations=result.get("recommendations", []),
            )

            logger.info(f"Generated CTI report: {report.report_id}")
            return report

        except Exception as e:
            logger.error(f"CTI report generation failed: {e}")
            raise

    def extract_iocs(self, report_text: str) -> List[IOC]:
        """
        Extract Indicators of Compromise from threat report

        Args:
            report_text: Threat intelligence report text

        Returns:
            List[IOC]: Extracted IOCs
        """
        logger.info("Extracting IOCs from report")

        system_message = """You are a threat intelligence analyst specializing in IOC extraction.
Extract all indicators of compromise from security reports including IPs, domains,
file hashes, URLs, email addresses, and registry keys."""

        prompt = f"""Extract all Indicators of Compromise (IOCs) from this threat report:

{report_text}

Identify and categorize all IOCs:
- IP addresses
- Domain names
- File hashes (MD5, SHA1, SHA256)
- URLs
- Email addresses
- Registry keys
- File paths

Respond in JSON format:
{{
    "iocs": [
        {{
            "type": "ip|domain|hash|url|email|registry|filepath",
            "value": "the actual IOC value",
            "description": "context from the report",
            "severity": "LOW|MEDIUM|HIGH|CRITICAL"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            iocs = []
            for ioc_data in result.get("iocs", []):
                ioc = IOC(
                    type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    description=ioc_data.get("description", ""),
                    severity=ioc_data.get("severity", "MEDIUM"),
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=[],
                )
                iocs.append(ioc)

            logger.info(f"Extracted {len(iocs)} IOCs")
            return iocs

        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            return []

    def profile_threat_actor(
        self, actor_name: str, campaign_data: Optional[Dict[str, Any]] = None
    ) -> ThreatActorProfile:
        """
        Create detailed threat actor profile

        Args:
            actor_name: Name or alias of threat actor
            campaign_data: Information about their campaigns

        Returns:
            ThreatActorProfile: Detailed actor profile
        """
        logger.info(f"Profiling threat actor: {actor_name}")

        system_message = """You are a threat intelligence analyst specializing in threat actor profiling.
Create detailed profiles based on known TTPs, motivations, and targeting patterns.
Use MITRE ATT&CK framework and industry threat intelligence."""

        campaign_str = (
            "\n".join([f"{k}: {v}" for k, v in campaign_data.items()])
            if campaign_data
            else "No campaign data provided"
        )

        prompt = f"""Create a comprehensive threat actor profile for: {actor_name}

Campaign Data:
{campaign_str}

Provide detailed profile in JSON format:
{{
    "aliases": ["list of known aliases"],
    "origin": "country or region of origin",
    "motivation": "financial|espionage|disruption|ideology",
    "sophistication": "low|medium|high|advanced",
    "target_sectors": ["list of targeted industry sectors"],
    "known_ttps": ["list of known TTPs with MITRE ATT&CK IDs"],
    "associated_campaigns": ["list of known campaign names"],
    "description": "detailed profile description"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            profile = ThreatActorProfile(
                name=actor_name,
                aliases=result.get("aliases", []),
                origin=result.get("origin", "Unknown"),
                motivation=result.get("motivation", "Unknown"),
                sophistication=result.get("sophistication", "medium"),
                target_sectors=result.get("target_sectors", []),
                known_ttps=result.get("known_ttps", []),
                associated_campaigns=result.get("associated_campaigns", []),
                description=result.get("description", ""),
            )

            logger.info(f"Created profile for {actor_name}")
            return profile

        except Exception as e:
            logger.error(f"Threat actor profiling failed: {e}")
            raise

    def correlate_threats(
        self, ioc_list: List[IOC], timeframe: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Correlate multiple IOCs to identify campaigns

        Args:
            ioc_list: List of IOCs to correlate
            timeframe: Time window for correlation

        Returns:
            Dict: Correlation analysis results
        """
        logger.info(f"Correlating {len(ioc_list)} IOCs")

        system_message = """You are a threat intelligence analyst specializing in threat correlation.
Identify patterns and relationships between IOCs to uncover coordinated campaigns."""

        # Format IOCs
        iocs_str = "\n".join(
            [
                f"- {ioc.type}: {ioc.value} (Severity: {ioc.severity})"
                for ioc in ioc_list
            ]
        )

        prompt = f"""Analyze these IOCs for correlation and campaign identification:

IOCs:
{iocs_str}

{f'Timeframe: {timeframe}' if timeframe else ''}

Identify:
1. Common patterns or relationships
2. Potential campaign affiliation
3. Threat actor attribution
4. Attack timeline
5. Infrastructure overlap

Respond in JSON format:
{{
    "campaign_identified": boolean,
    "campaign_name": "identified campaign name if any",
    "confidence": float (0-1),
    "threat_actor": "attributed threat actor if identified",
    "correlations": ["list of identified correlations"],
    "infrastructure_overlap": ["shared infrastructure elements"],
    "timeline": "attack timeline analysis",
    "recommendations": ["recommended actions"]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "total_iocs": len(ioc_list),
                "campaign_identified": result.get("campaign_identified", False),
                "campaign_name": result.get("campaign_name", "Unknown"),
                "confidence": result.get("confidence", 0.0),
                "threat_actor": result.get("threat_actor", "Unknown"),
                "correlations": result.get("correlations", []),
                "infrastructure_overlap": result.get("infrastructure_overlap", []),
                "timeline": result.get("timeline", ""),
                "recommendations": result.get("recommendations", []),
            }

        except Exception as e:
            logger.error(f"Threat correlation failed: {e}")
            return {"error": str(e)}

    def generate_yara_rule(self, malware_description: str) -> str:
        """
        Generate YARA rule from malware description

        Args:
            malware_description: Description of malware characteristics

        Returns:
            str: Generated YARA rule
        """
        logger.info("Generating YARA rule")

        system_message = """You are a malware analyst expert in writing YARA rules.
Generate effective YARA rules for malware detection based on descriptions."""

        prompt = f"""Generate a YARA rule to detect this malware:

{malware_description}

Create a well-documented YARA rule with:
1. Descriptive rule name
2. Metadata (author, date, description)
3. String patterns
4. Condition logic
5. Comments explaining the detection logic

Provide only the YARA rule code."""

        try:
            yara_rule = self.llm_client.complete(prompt, system_message=system_message)
            logger.info("YARA rule generated successfully")
            return yara_rule

        except Exception as e:
            logger.error(f"YARA rule generation failed: {e}")
            return f"// Error generating YARA rule: {e}"


# Example usage
if __name__ == "__main__":
    cti = CTIModule()

    # Test threat report generation
    print("=" * 50)
    print("Threat Intelligence Report Generation")
    print("=" * 50)

    incident_data = {
        "incident_type": "data_exfiltration",
        "source_ip": "203.0.113.50",
        "destination_ip": "198.51.100.10",
        "data_transferred": "15GB",
        "detection_time": "2025-01-01 14:30:00",
        "affected_systems": ["database-01", "file-server-02"],
    }

    report = cti.generate_threat_report(incident_data)
    print(f"Report ID: {report.report_id}")
    print(f"Title: {report.title}")
    print(f"Threat Actor: {report.threat_actor}")
    print(f"Severity: {report.severity}")
    print(f"IOCs Found: {len(report.iocs)}")
    print(f"\nExecutive Summary:\n{report.executive_summary}")

    # Test IOC extraction
    print("\n" + "=" * 50)
    print("IOC Extraction")
    print("=" * 50)

    sample_report = """
    The threat actor used IP 192.0.2.100 to connect to C2 server evil-domain.com.
    File hash: 5d41402abc4b2a76b9719d911017c592
    Malicious URL: http://malicious-site.net/payload.exe
    """

    iocs = cti.extract_iocs(sample_report)
    print(f"Extracted {len(iocs)} IOCs:")
    for ioc in iocs:
        print(f"  - {ioc.type}: {ioc.value} ({ioc.severity})")

    # Test threat actor profiling
    print("\n" + "=" * 50)
    print("Threat Actor Profiling")
    print("=" * 50)

    profile = cti.profile_threat_actor("APT28")
    print(f"Actor: {profile.name}")
    print(f"Origin: {profile.origin}")
    print(f"Motivation: {profile.motivation}")
    print(f"Sophistication: {profile.sophistication}")
    print(f"Target Sectors: {', '.join(profile.target_sectors)}")
