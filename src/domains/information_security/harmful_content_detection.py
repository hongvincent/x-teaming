"""
Harmful Content Detection Module
Detects toxic, harmful, and inappropriate content
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContentAnalysis:
    """Content toxicity analysis result"""

    content_id: str
    is_harmful: bool
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    categories: List[str]
    confidence: float
    specific_violations: List[str]
    context_analysis: str
    recommendation: str
    timestamp: str


@dataclass
class ModerationDecision:
    """Content moderation decision"""

    action: str  # allow, flag, remove, escalate
    reason: str
    confidence: float
    auto_action: bool
    human_review_required: bool


@dataclass
class ToxicityScore:
    """Toxicity scoring breakdown"""

    overall_score: float
    hate_speech: float
    harassment: float
    violence: float
    sexual_content: float
    profanity: float
    self_harm: float
    misinformation: float


class HarmfulContentDetectionModule:
    """
    Harmful Content Detection Module
    Uses LLM to detect and classify harmful, toxic, and inappropriate content
    """

    def __init__(self):
        """Initialize harmful content detection module"""
        self.llm_client = LLMClient()
        logger.info("Harmful Content Detection Module initialized")

    def analyze_content(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> ContentAnalysis:
        """
        Analyze content for harmful elements

        Args:
            content: Content to analyze
            context: Additional context (platform, audience, etc.)

        Returns:
            ContentAnalysis: Detailed toxicity analysis
        """
        logger.info("Analyzing content for harmful elements")

        system_message = """You are a content moderation expert specializing in detecting harmful content.
Analyze content for:
- Hate speech and discrimination
- Harassment and bullying
- Violence and threats
- Sexual content
- Self-harm and dangerous activities
- Misinformation and disinformation
- Profanity and offensive language

Consider context, intent, and cultural nuances."""

        context_str = ""
        if context:
            context_str = f"\nContext: {context}"

        prompt = f"""Analyze this content for harmful elements:

Content:
{content[:2000]}
{context_str}

Provide detailed analysis in JSON format:
{{
    "is_harmful": boolean,
    "severity": "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "categories": [list of applicable categories: "hate_speech", "harassment", "violence", "sexual", "self_harm", "misinformation", "profanity"],
    "confidence": float (0-1),
    "specific_violations": [list of specific violations found],
    "context_analysis": "analysis of context and intent",
    "recommendation": "recommended action"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            content_id = f"content_{datetime.now().timestamp()}"

            return ContentAnalysis(
                content_id=content_id,
                is_harmful=result.get("is_harmful", False),
                severity=result.get("severity", "NONE"),
                categories=result.get("categories", []),
                confidence=result.get("confidence", 0.0),
                specific_violations=result.get("specific_violations", []),
                context_analysis=result.get("context_analysis", ""),
                recommendation=result.get("recommendation", ""),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            return ContentAnalysis(
                content_id="error",
                is_harmful=False,
                severity="UNKNOWN",
                categories=[],
                confidence=0.0,
                specific_violations=[],
                context_analysis="",
                recommendation=f"Analysis error: {e}",
                timestamp=datetime.now().isoformat(),
            )

    def detect_hate_speech(
        self, text: str, target_groups: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Detect hate speech targeting specific groups

        Args:
            text: Text to analyze
            target_groups: List of potentially targeted groups

        Returns:
            Dict: Hate speech detection results
        """
        logger.info("Analyzing for hate speech")

        system_message = """You are a hate speech detection expert.
Identify hate speech, slurs, derogatory language, and discriminatory content.
Consider context, dog whistles, and coded language.
Distinguish between hate speech and legitimate criticism or satire."""

        target_str = ""
        if target_groups:
            target_str = f"\nPotential target groups: {', '.join(target_groups)}"

        prompt = f"""Analyze this text for hate speech:

Text: {text}
{target_str}

Provide analysis in JSON format:
{{
    "is_hate_speech": boolean,
    "confidence": float (0-1),
    "targeted_groups": [list of groups targeted],
    "hate_indicators": [specific indicators of hate speech],
    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "coded_language": [any dog whistles or coded language detected],
    "explanation": "detailed explanation"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "is_hate_speech": result.get("is_hate_speech", False),
                "confidence": result.get("confidence", 0.0),
                "targeted_groups": result.get("targeted_groups", []),
                "hate_indicators": result.get("hate_indicators", []),
                "severity": result.get("severity", "NONE"),
                "coded_language": result.get("coded_language", []),
                "explanation": result.get("explanation", ""),
            }

        except Exception as e:
            logger.error(f"Hate speech detection failed: {e}")
            return {"error": str(e), "is_hate_speech": False}

    def assess_toxicity_score(self, content: str) -> ToxicityScore:
        """
        Generate detailed toxicity scores across categories

        Args:
            content: Content to score

        Returns:
            ToxicityScore: Breakdown of toxicity scores
        """
        logger.info("Generating toxicity scores")

        system_message = """You are a content safety expert.
Score content toxicity across multiple dimensions on a scale of 0-1.
Be precise and consistent in scoring."""

        prompt = f"""Score the toxicity of this content across all categories:

Content:
{content[:2000]}

Provide scores (0-1) for each category in JSON format:
{{
    "overall_score": float (0-1),
    "hate_speech": float (0-1),
    "harassment": float (0-1),
    "violence": float (0-1),
    "sexual_content": float (0-1),
    "profanity": float (0-1),
    "self_harm": float (0-1),
    "misinformation": float (0-1)
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return ToxicityScore(
                overall_score=result.get("overall_score", 0.0),
                hate_speech=result.get("hate_speech", 0.0),
                harassment=result.get("harassment", 0.0),
                violence=result.get("violence", 0.0),
                sexual_content=result.get("sexual_content", 0.0),
                profanity=result.get("profanity", 0.0),
                self_harm=result.get("self_harm", 0.0),
                misinformation=result.get("misinformation", 0.0),
            )

        except Exception as e:
            logger.error(f"Toxicity scoring failed: {e}")
            return ToxicityScore(
                overall_score=0.0,
                hate_speech=0.0,
                harassment=0.0,
                violence=0.0,
                sexual_content=0.0,
                profanity=0.0,
                self_harm=0.0,
                misinformation=0.0,
            )

    def moderate_content(
        self, content: str, platform_policies: Dict[str, Any]
    ) -> ModerationDecision:
        """
        Make moderation decision based on platform policies

        Args:
            content: Content to moderate
            platform_policies: Platform-specific moderation policies

        Returns:
            ModerationDecision: Moderation decision
        """
        logger.info("Making moderation decision")

        system_message = """You are a content moderation decision engine.
Apply platform policies consistently and fairly.
Consider context, user history, and severity when making decisions."""

        policies_str = "\n".join([f"- {k}: {v}" for k, v in platform_policies.items()])

        prompt = f"""Make a moderation decision for this content based on platform policies:

Content:
{content[:2000]}

Platform Policies:
{policies_str}

Provide decision in JSON format:
{{
    "action": "allow" | "flag" | "remove" | "escalate",
    "reason": "detailed reason for decision",
    "confidence": float (0-1),
    "auto_action": boolean (can be handled automatically),
    "human_review_required": boolean
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return ModerationDecision(
                action=result.get("action", "flag"),
                reason=result.get("reason", ""),
                confidence=result.get("confidence", 0.0),
                auto_action=result.get("auto_action", False),
                human_review_required=result.get("human_review_required", True),
            )

        except Exception as e:
            logger.error(f"Moderation decision failed: {e}")
            return ModerationDecision(
                action="escalate",
                reason=f"Decision error: {e}",
                confidence=0.0,
                auto_action=False,
                human_review_required=True,
            )

    def detect_misinformation(
        self, claim: str, context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Detect potential misinformation and false claims

        Args:
            claim: Claim or statement to verify
            context: Additional context

        Returns:
            Dict: Misinformation analysis
        """
        logger.info("Analyzing for misinformation")

        system_message = """You are a fact-checking and misinformation detection expert.
Identify false claims, misleading information, and manipulation tactics.
Consider source credibility, evidence, and logical consistency.
Flag claims that need fact-checking."""

        prompt = f"""Analyze this claim for potential misinformation:

Claim: {claim}
{f'Context: {context}' if context else ''}

Provide analysis in JSON format:
{{
    "likely_misinformation": boolean,
    "confidence": float (0-1),
    "claim_type": "factual" | "opinion" | "prediction" | "mixed",
    "red_flags": [list of misinformation indicators],
    "verifiable": boolean,
    "fact_check_needed": boolean,
    "manipulation_tactics": [any detected manipulation tactics],
    "explanation": "detailed explanation"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "likely_misinformation": result.get("likely_misinformation", False),
                "confidence": result.get("confidence", 0.0),
                "claim_type": result.get("claim_type", "factual"),
                "red_flags": result.get("red_flags", []),
                "verifiable": result.get("verifiable", True),
                "fact_check_needed": result.get("fact_check_needed", False),
                "manipulation_tactics": result.get("manipulation_tactics", []),
                "explanation": result.get("explanation", ""),
            }

        except Exception as e:
            logger.error(f"Misinformation detection failed: {e}")
            return {"error": str(e), "likely_misinformation": False}


# Example usage
if __name__ == "__main__":
    detector = HarmfulContentDetectionModule()

    # Test general content analysis
    print("=" * 70)
    print("HARMFUL CONTENT DETECTION")
    print("=" * 70)

    harmful_content = """
    Those [slur] people don't belong here. They should all go back where they came from.
    We need to do something about this problem before it's too late.
    """

    analysis = detector.analyze_content(
        harmful_content, context={"platform": "social_media", "audience": "public"}
    )
    print(f"Is Harmful: {analysis.is_harmful}")
    print(f"Severity: {analysis.severity}")
    print(f"Confidence: {analysis.confidence:.2f}")
    print(f"Categories: {', '.join(analysis.categories)}")
    print(f"Recommendation: {analysis.recommendation}")

    # Test hate speech detection
    print("\n" + "=" * 70)
    print("HATE SPEECH DETECTION")
    print("=" * 70)

    hate_text = "All [group] are criminals and terrorists. They're ruining our country."

    hate_result = detector.detect_hate_speech(hate_text)
    print(f"Is Hate Speech: {hate_result['is_hate_speech']}")
    print(f"Confidence: {hate_result['confidence']:.2f}")
    print(f"Severity: {hate_result['severity']}")
    print(f"Targeted Groups: {', '.join(hate_result['targeted_groups'])}")

    # Test toxicity scoring
    print("\n" + "=" * 70)
    print("TOXICITY SCORING")
    print("=" * 70)

    toxic_content = "You're an absolute idiot. I hope something terrible happens to you!"

    scores = detector.assess_toxicity_score(toxic_content)
    print(f"Overall Score: {scores.overall_score:.2f}")
    print(f"Hate Speech: {scores.hate_speech:.2f}")
    print(f"Harassment: {scores.harassment:.2f}")
    print(f"Violence: {scores.violence:.2f}")
    print(f"Profanity: {scores.profanity:.2f}")

    # Test content moderation
    print("\n" + "=" * 70)
    print("CONTENT MODERATION DECISION")
    print("=" * 70)

    platform_policies = {
        "hate_speech": "zero tolerance",
        "harassment": "remove after warning",
        "violence": "immediate removal",
        "profanity": "filter but allow",
    }

    decision = detector.moderate_content(harmful_content, platform_policies)
    print(f"Action: {decision.action}")
    print(f"Reason: {decision.reason}")
    print(f"Confidence: {decision.confidence:.2f}")
    print(f"Auto Action: {decision.auto_action}")
    print(f"Human Review Required: {decision.human_review_required}")

    # Test misinformation detection
    print("\n" + "=" * 70)
    print("MISINFORMATION DETECTION")
    print("=" * 70)

    claim = "Vaccines contain microchips that the government uses to track your location."

    misinfo_result = detector.detect_misinformation(claim)
    print(f"Likely Misinformation: {misinfo_result['likely_misinformation']}")
    print(f"Confidence: {misinfo_result['confidence']:.2f}")
    print(f"Claim Type: {misinfo_result['claim_type']}")
    print(f"Fact Check Needed: {misinfo_result['fact_check_needed']}")
    print(f"Red Flags: {', '.join(misinfo_result['red_flags'][:3])}")
