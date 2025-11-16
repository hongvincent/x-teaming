"""
Phishing Detection Module
Detects phishing attempts in emails and URLs
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PhishingAnalysis:
    """Phishing analysis result"""

    is_phishing: bool
    confidence: float
    phishing_type: str  # email, url, sms, voice
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    indicators: List[str]
    spoofed_entity: Optional[str]
    attack_techniques: List[str]
    recommendation: str
    timestamp: str


@dataclass
class EmailAnalysis:
    """Email phishing analysis result"""

    email_id: str
    is_phishing: bool
    confidence: float
    phishing_indicators: List[str]
    sender_reputation: str
    link_analysis: List[Dict[str, Any]]
    attachment_analysis: List[Dict[str, Any]]
    urgency_tactics: List[str]
    brand_impersonation: Optional[str]
    risk_score: float


@dataclass
class URLAnalysis:
    """URL phishing analysis result"""

    url: str
    is_phishing: bool
    confidence: float
    domain_reputation: str
    similarity_to_legitimate: Optional[str]
    suspicious_patterns: List[str]
    typosquatting: bool
    threat_indicators: List[str]


class PhishingDetectionModule:
    """
    Phishing Detection Module
    Uses LLM to detect phishing attempts in emails, URLs, and messages
    """

    def __init__(self):
        """Initialize phishing detection module"""
        self.llm_client = LLMClient()
        logger.info("Phishing Detection Module initialized")

    def analyze_email(
        self, email_content: str, metadata: Optional[Dict[str, Any]] = None
    ) -> EmailAnalysis:
        """
        Analyze email for phishing indicators

        Args:
            email_content: Email body content
            metadata: Email metadata (sender, subject, headers, etc.)

        Returns:
            EmailAnalysis: Detailed phishing analysis
        """
        logger.info("Analyzing email for phishing indicators")

        system_message = """You are a cybersecurity expert specializing in phishing detection.
Analyze emails for phishing indicators including:
- Sender spoofing and domain verification
- Suspicious links and URLs
- Social engineering tactics
- Brand impersonation
- Urgency and pressure tactics
- Grammar and spelling anomalies
- Attachment risks"""

        metadata_str = ""
        if metadata:
            metadata_str = f"""
Email Metadata:
- From: {metadata.get('from', 'Unknown')}
- Subject: {metadata.get('subject', 'No subject')}
- Reply-To: {metadata.get('reply_to', 'N/A')}
- Date: {metadata.get('date', 'Unknown')}
"""

        prompt = f"""Analyze this email for phishing:

{metadata_str}

Email Content:
{email_content[:2000]}

Provide detailed analysis in JSON format:
{{
    "is_phishing": boolean,
    "confidence": float (0-1),
    "phishing_indicators": [list of specific indicators found],
    "sender_reputation": "trusted" | "suspicious" | "malicious" | "unknown",
    "link_analysis": [
        {{
            "url": "extracted URL",
            "suspicious": boolean,
            "reason": "explanation"
        }}
    ],
    "attachment_analysis": [
        {{
            "filename": "attachment name",
            "risk": "low" | "medium" | "high",
            "reason": "explanation"
        }}
    ],
    "urgency_tactics": [list of urgency/pressure tactics used],
    "brand_impersonation": "brand name or null",
    "risk_score": float (0-10)
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            email_id = metadata.get("message_id", f"email_{datetime.now().timestamp()}")

            return EmailAnalysis(
                email_id=email_id,
                is_phishing=result.get("is_phishing", False),
                confidence=result.get("confidence", 0.0),
                phishing_indicators=result.get("phishing_indicators", []),
                sender_reputation=result.get("sender_reputation", "unknown"),
                link_analysis=result.get("link_analysis", []),
                attachment_analysis=result.get("attachment_analysis", []),
                urgency_tactics=result.get("urgency_tactics", []),
                brand_impersonation=result.get("brand_impersonation"),
                risk_score=result.get("risk_score", 0.0),
            )

        except Exception as e:
            logger.error(f"Email phishing analysis failed: {e}")
            return EmailAnalysis(
                email_id="error",
                is_phishing=False,
                confidence=0.0,
                phishing_indicators=[],
                sender_reputation="unknown",
                link_analysis=[],
                attachment_analysis=[],
                urgency_tactics=[],
                brand_impersonation=None,
                risk_score=0.0,
            )

    def analyze_url(self, url: str, context: Optional[str] = None) -> URLAnalysis:
        """
        Analyze URL for phishing indicators

        Args:
            url: URL to analyze
            context: Additional context (e.g., where URL was found)

        Returns:
            URLAnalysis: URL phishing analysis
        """
        logger.info(f"Analyzing URL for phishing: {url}")

        system_message = """You are a URL security expert specializing in phishing detection.
Analyze URLs for phishing indicators including:
- Domain typosquatting and look-alike domains
- Suspicious TLDs (.xyz, .tk, etc.)
- URL obfuscation techniques
- Homograph attacks (using unicode lookalikes)
- Subdomain abuse
- Shortened URLs
- Parameter injection"""

        prompt = f"""Analyze this URL for phishing:

URL: {url}
{f'Context: {context}' if context else ''}

Provide analysis in JSON format:
{{
    "is_phishing": boolean,
    "confidence": float (0-1),
    "domain_reputation": "legitimate" | "suspicious" | "malicious" | "unknown",
    "similarity_to_legitimate": "legitimate domain it mimics or null",
    "suspicious_patterns": [list of suspicious patterns found],
    "typosquatting": boolean,
    "threat_indicators": [list of specific threats]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return URLAnalysis(
                url=url,
                is_phishing=result.get("is_phishing", False),
                confidence=result.get("confidence", 0.0),
                domain_reputation=result.get("domain_reputation", "unknown"),
                similarity_to_legitimate=result.get("similarity_to_legitimate"),
                suspicious_patterns=result.get("suspicious_patterns", []),
                typosquatting=result.get("typosquatting", False),
                threat_indicators=result.get("threat_indicators", []),
            )

        except Exception as e:
            logger.error(f"URL phishing analysis failed: {e}")
            return URLAnalysis(
                url=url,
                is_phishing=False,
                confidence=0.0,
                domain_reputation="unknown",
                similarity_to_legitimate=None,
                suspicious_patterns=[],
                typosquatting=False,
                threat_indicators=[],
            )

    def detect_spear_phishing(
        self, email_content: str, target_profile: Dict[str, Any]
    ) -> PhishingAnalysis:
        """
        Detect targeted spear phishing attacks

        Args:
            email_content: Email content
            target_profile: Information about the target (role, organization, etc.)

        Returns:
            PhishingAnalysis: Spear phishing analysis
        """
        logger.info("Analyzing for spear phishing attack")

        system_message = """You are an advanced threat analyst specializing in spear phishing detection.
Spear phishing uses personalized information to target specific individuals.
Look for: personalized content, role-specific requests, organizational knowledge, and social engineering."""

        profile_str = "\n".join([f"- {k}: {v}" for k, v in target_profile.items()])

        prompt = f"""Analyze this email for spear phishing targeting this individual:

Target Profile:
{profile_str}

Email Content:
{email_content[:2000]}

Assess if this is a targeted spear phishing attack:
{{
    "is_phishing": boolean,
    "confidence": float (0-1),
    "phishing_type": "spear_phishing" | "whaling" | "business_email_compromise" | "generic",
    "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "indicators": [list of personalization and targeting indicators],
    "spoofed_entity": "entity being impersonated or null",
    "attack_techniques": [list of social engineering techniques used],
    "recommendation": "detailed recommendation"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return PhishingAnalysis(
                is_phishing=result.get("is_phishing", False),
                confidence=result.get("confidence", 0.0),
                phishing_type=result.get("phishing_type", "generic"),
                threat_level=result.get("threat_level", "LOW"),
                indicators=result.get("indicators", []),
                spoofed_entity=result.get("spoofed_entity"),
                attack_techniques=result.get("attack_techniques", []),
                recommendation=result.get("recommendation", ""),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Spear phishing detection failed: {e}")
            return PhishingAnalysis(
                is_phishing=False,
                confidence=0.0,
                phishing_type="error",
                threat_level="UNKNOWN",
                indicators=[],
                spoofed_entity=None,
                attack_techniques=[],
                recommendation=f"Analysis error: {e}",
                timestamp=datetime.now().isoformat(),
            )

    def analyze_sms_phishing(self, sms_content: str, sender: str) -> PhishingAnalysis:
        """
        Detect SMS phishing (smishing) attacks

        Args:
            sms_content: SMS message content
            sender: Sender phone number or ID

        Returns:
            PhishingAnalysis: SMS phishing analysis
        """
        logger.info("Analyzing SMS for phishing (smishing)")

        system_message = """You are a mobile security expert specializing in SMS phishing detection.
Analyze SMS messages for smishing indicators including:
- Suspicious sender numbers
- Urgency tactics
- Links to malicious sites
- Requests for personal information
- Brand impersonation
- Prize/lottery scams"""

        prompt = f"""Analyze this SMS message for phishing (smishing):

Sender: {sender}
Message: {sms_content}

Provide analysis in JSON format:
{{
    "is_phishing": boolean,
    "confidence": float (0-1),
    "phishing_type": "smishing",
    "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "indicators": [list of smishing indicators],
    "spoofed_entity": "brand/entity being impersonated or null",
    "attack_techniques": [list of techniques used],
    "recommendation": "action to take"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return PhishingAnalysis(
                is_phishing=result.get("is_phishing", False),
                confidence=result.get("confidence", 0.0),
                phishing_type="smishing",
                threat_level=result.get("threat_level", "LOW"),
                indicators=result.get("indicators", []),
                spoofed_entity=result.get("spoofed_entity"),
                attack_techniques=result.get("attack_techniques", []),
                recommendation=result.get("recommendation", ""),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"SMS phishing analysis failed: {e}")
            return PhishingAnalysis(
                is_phishing=False,
                confidence=0.0,
                phishing_type="smishing",
                threat_level="UNKNOWN",
                indicators=[],
                spoofed_entity=None,
                attack_techniques=[],
                recommendation=f"Analysis error: {e}",
                timestamp=datetime.now().isoformat(),
            )


# Example usage
if __name__ == "__main__":
    detector = PhishingDetectionModule()

    # Test email phishing detection
    print("=" * 70)
    print("EMAIL PHISHING DETECTION")
    print("=" * 70)

    email_content = """
    Dear Valued Customer,

    Your account has been SUSPENDED due to suspicious activity!
    You must verify your identity within 24 hours or your account will be permanently closed.

    Click here to verify: http://paypa1-verify.tk/secure-login

    This is urgent - do not delay!

    PayPal Security Team
    """

    email_metadata = {
        "from": "security@paypa1-alerts.com",
        "subject": "URGENT: Account Suspended - Action Required",
        "reply_to": "noreply@randomdomain.xyz",
        "date": "2025-01-15",
    }

    email_result = detector.analyze_email(email_content, email_metadata)
    print(f"Is Phishing: {email_result.is_phishing}")
    print(f"Confidence: {email_result.confidence:.2f}")
    print(f"Risk Score: {email_result.risk_score}/10")
    print(f"Sender Reputation: {email_result.sender_reputation}")
    print(f"Brand Impersonation: {email_result.brand_impersonation}")
    print(f"\nPhishing Indicators:")
    for indicator in email_result.phishing_indicators[:5]:
        print(f"  - {indicator}")

    # Test URL phishing detection
    print("\n" + "=" * 70)
    print("URL PHISHING DETECTION")
    print("=" * 70)

    test_urls = [
        "https://google.com",
        "http://g00gle-login.tk/signin",
        "https://github.com/user/repo",
    ]

    for url in test_urls:
        url_result = detector.analyze_url(url)
        print(f"\nURL: {url_result.url}")
        print(f"Is Phishing: {url_result.is_phishing}")
        print(f"Confidence: {url_result.confidence:.2f}")
        print(f"Domain Reputation: {url_result.domain_reputation}")
        if url_result.similarity_to_legitimate:
            print(f"Mimics: {url_result.similarity_to_legitimate}")

    # Test spear phishing detection
    print("\n" + "=" * 70)
    print("SPEAR PHISHING DETECTION")
    print("=" * 70)

    target_profile = {
        "name": "John Smith",
        "role": "CFO",
        "organization": "TechCorp Inc",
        "department": "Finance",
    }

    spear_email = """
    Hi John,

    I hope this email finds you well. As discussed in yesterday's board meeting,
    we need to process the urgent wire transfer to finalize the acquisition.

    Please review and approve the attached invoice for $250,000.
    Time is of the essence as the deal closes Friday.

    Best regards,
    Michael Chen
    CEO, TechCorp Inc
    """

    spear_result = detector.detect_spear_phishing(spear_email, target_profile)
    print(f"Is Spear Phishing: {spear_result.is_phishing}")
    print(f"Confidence: {spear_result.confidence:.2f}")
    print(f"Attack Type: {spear_result.phishing_type}")
    print(f"Threat Level: {spear_result.threat_level}")
    print(f"Recommendation: {spear_result.recommendation[:100]}...")

    # Test SMS phishing detection
    print("\n" + "=" * 70)
    print("SMS PHISHING (SMISHING) DETECTION")
    print("=" * 70)

    sms_content = "CONGRATULATIONS! You've won $1000 Amazon gift card! Claim now: bit.ly/claim123. Expires in 2 hours!"
    sms_sender = "+1-555-SCAM"

    sms_result = detector.analyze_sms_phishing(sms_content, sms_sender)
    print(f"Is Smishing: {sms_result.is_phishing}")
    print(f"Confidence: {sms_result.confidence:.2f}")
    print(f"Threat Level: {sms_result.threat_level}")
    print(f"Indicators: {', '.join(sms_result.indicators[:3])}")
