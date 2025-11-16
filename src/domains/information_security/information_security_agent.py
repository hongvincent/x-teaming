"""
Information Security Agent
Coordinates all information security modules
"""

from typing import Dict, Any, List, Optional

from .phishing_detection import PhishingDetectionModule
from .harmful_content_detection import HarmfulContentDetectionModule
from .steganography import SteganographyModule
from .access_control import AccessControlModule
from .digital_forensics import DigitalForensicsModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class InformationSecurityAgent:
    """
    Information Security Agent
    Coordinates phishing detection, content moderation, steganography, access control, and digital forensics
    """

    def __init__(self):
        """Initialize Information Security Agent"""
        self.config = get_config()

        # Initialize modules
        self.phishing = PhishingDetectionModule()
        self.content_detection = HarmfulContentDetectionModule()
        self.steganography = SteganographyModule()
        self.access_control = AccessControlModule()
        self.forensics = DigitalForensicsModule()

        logger.info("Information Security Agent initialized with all modules")

    def comprehensive_email_analysis(
        self, email_content: str, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive email security analysis

        Args:
            email_content: Email content
            metadata: Email metadata

        Returns:
            Dict: Complete analysis results
        """
        logger.info("Performing comprehensive email analysis")

        results = {}

        try:
            # Phishing detection
            phishing_result = self.phishing.analyze_email(email_content, metadata)
            results["phishing_analysis"] = {
                "is_phishing": phishing_result.is_phishing,
                "confidence": phishing_result.confidence,
                "risk_score": phishing_result.risk_score,
                "brand_impersonation": phishing_result.brand_impersonation,
            }

            # Harmful content detection
            content_result = self.content_detection.analyze_content(email_content)
            results["content_analysis"] = {
                "is_harmful": content_result.is_harmful,
                "severity": content_result.severity,
                "categories": content_result.categories,
            }

            # Steganography detection
            stego_result = self.steganography.analyze_text_steganography(email_content)
            results["steganography"] = {
                "hidden_message_detected": stego_result.hidden_message_detected,
                "technique": stego_result.technique,
            }

            # Overall risk assessment
            risk_factors = []
            if phishing_result.is_phishing:
                risk_factors.append("phishing")
            if content_result.is_harmful:
                risk_factors.append("harmful_content")
            if stego_result.hidden_message_detected:
                risk_factors.append("steganography")

            results["overall_risk"] = {
                "risk_level": "HIGH" if len(risk_factors) > 0 else "LOW",
                "risk_factors": risk_factors,
                "recommendation": "Block and quarantine"
                if len(risk_factors) > 0
                else "Safe to deliver",
            }

            return results

        except Exception as e:
            logger.error(f"Comprehensive email analysis failed: {e}")
            return {"error": str(e)}

    def analyze_user_content(
        self, content: str, platform_policies: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze user-generated content for moderation

        Args:
            content: User content to analyze
            platform_policies: Platform moderation policies

        Returns:
            Dict: Moderation decision and analysis
        """
        logger.info("Analyzing user content for moderation")

        try:
            # Toxicity analysis
            toxicity_scores = self.content_detection.assess_toxicity_score(content)

            # Harmful content detection
            content_analysis = self.content_detection.analyze_content(content)

            # Moderation decision
            moderation = self.content_detection.moderate_content(
                content, platform_policies
            )

            return {
                "toxicity_scores": {
                    "overall": toxicity_scores.overall_score,
                    "hate_speech": toxicity_scores.hate_speech,
                    "harassment": toxicity_scores.harassment,
                    "violence": toxicity_scores.violence,
                },
                "content_analysis": {
                    "is_harmful": content_analysis.is_harmful,
                    "severity": content_analysis.severity,
                    "categories": content_analysis.categories,
                },
                "moderation_decision": {
                    "action": moderation.action,
                    "reason": moderation.reason,
                    "confidence": moderation.confidence,
                    "human_review_required": moderation.human_review_required,
                },
            }

        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            return {"error": str(e)}

    def security_audit(
        self, auth_config: Dict[str, Any], access_policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform security audit of authentication and access control

        Args:
            auth_config: Authentication configuration
            access_policy: Access control policy

        Returns:
            Dict: Audit results
        """
        logger.info("Performing security audit")

        try:
            # Authentication analysis
            auth_result = self.access_control.analyze_authentication_mechanism(
                auth_config
            )

            # Access policy analysis
            policy_result = self.access_control.analyze_access_policy(
                access_policy, []
            )

            # Overall security score
            security_score = (
                auth_result.security_score * 0.6
                + (100 if policy_result.principle_of_least_privilege else 0) * 0.4
            )

            return {
                "authentication": {
                    "security_score": auth_result.security_score,
                    "mfa_enabled": auth_result.mfa_enabled,
                    "vulnerabilities": auth_result.vulnerabilities,
                    "compliance": auth_result.compliance,
                },
                "access_control": {
                    "least_privilege": policy_result.principle_of_least_privilege,
                    "separation_of_duties": policy_result.separation_of_duties,
                    "security_gaps": policy_result.security_gaps,
                },
                "overall_security_score": security_score,
                "recommendations": auth_result.recommendations
                + policy_result.recommendations,
            }

        except Exception as e:
            logger.error(f"Security audit failed: {e}")
            return {"error": str(e)}

    def investigate_incident(
        self, disk_metadata: Dict[str, Any], memory_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Investigate security incident using forensic analysis

        Args:
            disk_metadata: Disk image metadata
            memory_data: Memory dump data

        Returns:
            Dict: Investigation results
        """
        logger.info("Investigating security incident")

        try:
            # Disk forensics
            disk_analysis = self.forensics.analyze_disk_image(disk_metadata, [])

            # Memory forensics
            memory_analysis = self.forensics.analyze_memory_dump(memory_data)

            # Compile findings
            all_iocs = disk_analysis.indicators_of_compromise
            if memory_analysis.malware_detected:
                all_iocs.append("Malware detected in memory")

            return {
                "incident_type": disk_analysis.incident_type,
                "timeline_events": len(disk_analysis.timeline),
                "evidence_collected": len(disk_analysis.evidence_collected),
                "malware_detected": memory_analysis.malware_detected,
                "indicators_of_compromise": all_iocs,
                "key_findings": disk_analysis.key_findings,
                "persistence_mechanisms": memory_analysis.persistence_mechanisms,
                "recommendations": disk_analysis.recommendations,
            }

        except Exception as e:
            logger.error(f"Incident investigation failed: {e}")
            return {"error": str(e)}

    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get agent status and capabilities

        Returns:
            Dict: Agent status information
        """
        return {
            "agent_name": "Information Security Agent",
            "status": "active",
            "modules": {
                "phishing_detection": "active",
                "harmful_content_detection": "active",
                "steganography": "active",
                "access_control": "active",
                "digital_forensics": "active",
            },
            "capabilities": [
                "Email and URL phishing detection",
                "Harmful content and toxicity detection",
                "Steganography detection (text, image, audio, network)",
                "Password strength analysis",
                "Authentication mechanism security audit",
                "Access control policy validation",
                "Digital forensics and incident investigation",
                "Timeline reconstruction",
            ],
        }


# Example usage
if __name__ == "__main__":
    agent = InformationSecurityAgent()

    # Get agent status
    print("=" * 70)
    print("INFORMATION SECURITY AGENT STATUS")
    print("=" * 70)
    status = agent.get_agent_status()
    print(f"Agent: {status['agent_name']}")
    print(f"Status: {status['status']}")
    print("\nCapabilities:")
    for capability in status["capabilities"]:
        print(f"  - {capability}")

    # Test email analysis
    print("\n" + "=" * 70)
    print("COMPREHENSIVE EMAIL ANALYSIS")
    print("=" * 70)

    email = """
    URGENT: Your account has been suspended!
    Click here immediately to verify: http://paypa1-secure.tk
    """
    metadata = {
        "from": "security@fake-paypal.com",
        "subject": "Account Suspended",
        "date": "2025-01-15",
    }

    email_results = agent.comprehensive_email_analysis(email, metadata)
    print(f"Phishing: {email_results['phishing_analysis']['is_phishing']}")
    print(f"Risk Score: {email_results['phishing_analysis']['risk_score']}")
    print(f"Harmful Content: {email_results['content_analysis']['is_harmful']}")
    print(f"Overall Risk: {email_results['overall_risk']['risk_level']}")

    # Test content moderation
    print("\n" + "=" * 70)
    print("CONTENT MODERATION")
    print("=" * 70)

    user_content = "You're such an idiot! I hate you and hope bad things happen to you!"
    policies = {
        "hate_speech": "zero tolerance",
        "harassment": "remove",
    }

    mod_results = agent.analyze_user_content(user_content, policies)
    print(
        f"Overall Toxicity: {mod_results['toxicity_scores']['overall']:.2f}"
    )
    print(f"Action: {mod_results['moderation_decision']['action']}")
    print(
        f"Human Review: {mod_results['moderation_decision']['human_review_required']}"
    )

    # Test security audit
    print("\n" + "=" * 70)
    print("SECURITY AUDIT")
    print("=" * 70)

    auth_config = {
        "method": "password + TOTP",
        "mfa": "required",
        "session_timeout": 30,
    }
    access_policy = {"default_deny": True, "audit_logging": True}

    audit_results = agent.security_audit(auth_config, access_policy)
    print(f"Overall Security Score: {audit_results['overall_security_score']:.1f}/100")
    print(
        f"MFA Enabled: {audit_results['authentication']['mfa_enabled']}"
    )
    print(
        f"Least Privilege: {audit_results['access_control']['least_privilege']}"
    )
