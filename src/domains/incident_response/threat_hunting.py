"""
Threat Hunting Module
Proactive threat detection and hunting
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class HuntingHypothesis:
    """Threat hunting hypothesis"""

    hypothesis_id: str
    description: str
    threat_scenario: str
    data_sources: List[str]
    search_queries: List[str]
    expected_indicators: List[str]
    mitre_techniques: List[str]


@dataclass
class HuntingFinding:
    """Threat hunting finding"""

    finding_id: str
    hypothesis_tested: str
    threat_detected: bool
    confidence: float
    evidence: List[str]
    affected_systems: List[str]
    severity: str
    next_steps: List[str]


class ThreatHuntingModule:
    """
    Threat Hunting Module
    Proactive threat detection through hypothesis-driven hunting
    """

    def __init__(self):
        """Initialize threat hunting module"""
        self.llm_client = LLMClient()
        logger.info("Threat Hunting Module initialized")

    def generate_hunting_hypothesis(
        self, environment: Dict[str, Any], threat_landscape: str
    ) -> HuntingHypothesis:
        """Generate threat hunting hypothesis"""
        logger.info("Generating hunting hypothesis")

        system_message = """You are a threat hunter.
Create actionable hunting hypotheses based on:
- Current threat landscape
- Environment characteristics
- MITRE ATT&CK framework
- Known adversary behaviors"""

        env_str = "\n".join([f"{k}: {v}" for k, v in environment.items()])

        prompt = f"""Generate a threat hunting hypothesis:

Environment:
{env_str}

Threat Landscape: {threat_landscape}

Provide hypothesis in JSON format:
{{
    "description": "hypothesis description",
    "threat_scenario": "specific threat scenario to hunt",
    "data_sources": [required data sources],
    "search_queries": [specific queries to run],
    "expected_indicators": [what to look for],
    "mitre_techniques": ["T1566", "T1059"]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return HuntingHypothesis(
                hypothesis_id=f"hunt_{datetime.now().timestamp()}",
                description=result.get("description", ""),
                threat_scenario=result.get("threat_scenario", ""),
                data_sources=result.get("data_sources", []),
                search_queries=result.get("search_queries", []),
                expected_indicators=result.get("expected_indicators", []),
                mitre_techniques=result.get("mitre_techniques", []),
            )

        except Exception as e:
            logger.error(f"Hypothesis generation failed: {e}")
            return HuntingHypothesis(
                hypothesis_id="error",
                description="",
                threat_scenario="",
                data_sources=[],
                search_queries=[],
                expected_indicators=[],
                mitre_techniques=[],
            )

    def analyze_hunting_results(
        self, hypothesis: HuntingHypothesis, results: List[Dict[str, Any]]
    ) -> HuntingFinding:
        """Analyze threat hunting results"""
        logger.info("Analyzing hunting results")

        system_message = """You are a threat hunter analyzing search results.
Determine if hypothesis is confirmed and assess threat severity."""

        results_str = "\n".join([str(r) for r in results[:10]])

        prompt = f"""Analyze these hunting results:

Hypothesis: {hypothesis.description}
Expected: {', '.join(hypothesis.expected_indicators)}

Results:
{results_str}

Provide analysis in JSON format:
{{
    "threat_detected": boolean,
    "confidence": float (0-1),
    "evidence": [supporting evidence],
    "affected_systems": [affected systems],
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
    "next_steps": [recommended next steps]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)

            return HuntingFinding(
                finding_id=f"finding_{datetime.now().timestamp()}",
                hypothesis_tested=hypothesis.description,
                threat_detected=result.get("threat_detected", False),
                confidence=result.get("confidence", 0.0),
                evidence=result.get("evidence", []),
                affected_systems=result.get("affected_systems", []),
                severity=result.get("severity", "NONE"),
                next_steps=result.get("next_steps", []),
            )

        except Exception as e:
            logger.error(f"Results analysis failed: {e}")
            return HuntingFinding(
                finding_id="error",
                hypothesis_tested=hypothesis.description,
                threat_detected=False,
                confidence=0.0,
                evidence=[],
                affected_systems=[],
                severity="UNKNOWN",
                next_steps=[f"Analysis error: {e}"],
            )


# Example usage
if __name__ == "__main__":
    hunter = ThreatHuntingModule()

    environment = {
        "industry": "Financial Services",
        "critical_assets": ["trading_platform", "customer_db"],
        "recent_threats": "Ransomware targeting financial sector",
    }

    hypothesis = hunter.generate_hunting_hypothesis(
        environment, "Ransomware groups targeting finance"
    )
    print(f"Hypothesis: {hypothesis.description}")
    print(f"MITRE: {', '.join(hypothesis.mitre_techniques)}")
