"""
Access Control Module
Password strength analysis, authentication security, and access policy validation
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import re

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PasswordAnalysis:
    """Password strength analysis result"""

    password_hash: str
    strength_score: float  # 0-100
    strength_level: str  # WEAK, FAIR, GOOD, STRONG, VERY_STRONG
    entropy_bits: float
    vulnerabilities: List[str]
    recommendations: List[str]
    estimated_crack_time: str
    passes_policy: bool


@dataclass
class AuthenticationAnalysis:
    """Authentication mechanism analysis"""

    auth_method: str
    security_score: float
    vulnerabilities: List[str]
    mfa_enabled: bool
    session_management: str
    recommendations: List[str]
    compliance: Dict[str, bool]


@dataclass
class AccessPolicyAnalysis:
    """Access control policy analysis"""

    policy_id: str
    principle_of_least_privilege: bool
    separation_of_duties: bool
    policy_conflicts: List[str]
    over_privileged_accounts: List[str]
    security_gaps: List[str]
    recommendations: List[str]


class AccessControlModule:
    """
    Access Control Module
    Analyzes password strength, authentication mechanisms, and access policies
    """

    def __init__(self):
        """Initialize access control module"""
        self.llm_client = LLMClient()
        logger.info("Access Control Module initialized")

    def analyze_password_strength(
        self, password: str, user_info: Optional[Dict[str, Any]] = None
    ) -> PasswordAnalysis:
        """
        Analyze password strength and security

        Args:
            password: Password to analyze (will be hashed for privacy)
            user_info: User information to check for common patterns

        Returns:
            PasswordAnalysis: Comprehensive password analysis
        """
        logger.info("Analyzing password strength")

        # Basic analysis
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        # Calculate entropy (simplified)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        import math

        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        system_message = """You are a password security expert.
Analyze password strength considering:
- Length and complexity
- Character diversity
- Common patterns and dictionary words
- Keyboard patterns (qwerty, 123456)
- Personal information usage
- Known breached password databases"""

        # Mask password for LLM (show pattern only)
        pattern = self._get_password_pattern(password)
        user_str = ""
        if user_info:
            user_str = f"\nUser Info: {user_info}"

        prompt = f"""Analyze this password pattern for security:

Password Pattern: {pattern}
Length: {length}
Character Types: Upper={has_upper}, Lower={has_lower}, Digits={has_digit}, Special={has_special}
Estimated Entropy: {entropy:.2f} bits
{user_str}

Provide comprehensive analysis in JSON format:
{{
    "strength_score": float (0-100),
    "strength_level": "WEAK" | "FAIR" | "GOOD" | "STRONG" | "VERY_STRONG",
    "vulnerabilities": [list of weaknesses found],
    "recommendations": [list of improvement suggestions],
    "estimated_crack_time": "time estimate (e.g., '2 hours', '50 years')",
    "passes_policy": boolean (meets standard enterprise password policy)
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            # Hash the password for storage (simplified)
            import hashlib

            password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]

            return PasswordAnalysis(
                password_hash=password_hash,
                strength_score=result.get("strength_score", 0.0),
                strength_level=result.get("strength_level", "WEAK"),
                entropy_bits=entropy,
                vulnerabilities=result.get("vulnerabilities", []),
                recommendations=result.get("recommendations", []),
                estimated_crack_time=result.get("estimated_crack_time", "unknown"),
                passes_policy=result.get("passes_policy", False),
            )

        except Exception as e:
            logger.error(f"Password analysis failed: {e}")
            return PasswordAnalysis(
                password_hash="error",
                strength_score=0.0,
                strength_level="UNKNOWN",
                entropy_bits=entropy,
                vulnerabilities=[],
                recommendations=[f"Analysis error: {e}"],
                estimated_crack_time="unknown",
                passes_policy=False,
            )

    def analyze_authentication_mechanism(
        self, auth_config: Dict[str, Any]
    ) -> AuthenticationAnalysis:
        """
        Analyze authentication mechanism security

        Args:
            auth_config: Authentication configuration

        Returns:
            AuthenticationAnalysis: Security analysis
        """
        logger.info("Analyzing authentication mechanism")

        system_message = """You are an authentication security expert.
Analyze authentication mechanisms for security weaknesses:
- Password policies
- Multi-factor authentication (MFA)
- Session management
- Token security
- Brute force protection
- Account lockout policies
- Password reset procedures"""

        config_str = "\n".join([f"{k}: {v}" for k, v in auth_config.items()])

        prompt = f"""Analyze this authentication configuration:

Configuration:
{config_str}

Provide security analysis in JSON format:
{{
    "security_score": float (0-100),
    "vulnerabilities": [list of security issues],
    "mfa_enabled": boolean,
    "session_management": "secure" | "moderate" | "weak",
    "recommendations": [list of security improvements],
    "compliance": {{
        "NIST": boolean,
        "OWASP": boolean,
        "PCI_DSS": boolean
    }}
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return AuthenticationAnalysis(
                auth_method=auth_config.get("method", "unknown"),
                security_score=result.get("security_score", 0.0),
                vulnerabilities=result.get("vulnerabilities", []),
                mfa_enabled=result.get("mfa_enabled", False),
                session_management=result.get("session_management", "unknown"),
                recommendations=result.get("recommendations", []),
                compliance=result.get("compliance", {}),
            )

        except Exception as e:
            logger.error(f"Authentication analysis failed: {e}")
            return AuthenticationAnalysis(
                auth_method="error",
                security_score=0.0,
                vulnerabilities=[],
                mfa_enabled=False,
                session_management="unknown",
                recommendations=[f"Analysis error: {e}"],
                compliance={},
            )

    def analyze_access_policy(
        self, policy: Dict[str, Any], roles: List[Dict[str, Any]]
    ) -> AccessPolicyAnalysis:
        """
        Analyze access control policies

        Args:
            policy: Access control policy definition
            roles: User roles and permissions

        Returns:
            AccessPolicyAnalysis: Policy analysis
        """
        logger.info("Analyzing access control policy")

        system_message = """You are an access control security expert.
Analyze policies for:
- Principle of least privilege
- Separation of duties
- Role-based access control (RBAC)
- Privilege escalation risks
- Policy conflicts
- Over-privileged accounts
- Security gaps"""

        policy_str = "\n".join([f"{k}: {v}" for k, v in policy.items()])
        roles_str = "\n".join([str(role) for role in roles])

        prompt = f"""Analyze this access control policy:

Policy:
{policy_str}

Roles:
{roles_str}

Provide security analysis in JSON format:
{{
    "principle_of_least_privilege": boolean,
    "separation_of_duties": boolean,
    "policy_conflicts": [list of conflicting policies],
    "over_privileged_accounts": [list of accounts with excessive privileges],
    "security_gaps": [list of security gaps or missing controls],
    "recommendations": [list of policy improvements]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            policy_id = f"policy_{datetime.now().timestamp()}"

            return AccessPolicyAnalysis(
                policy_id=policy_id,
                principle_of_least_privilege=result.get(
                    "principle_of_least_privilege", False
                ),
                separation_of_duties=result.get("separation_of_duties", False),
                policy_conflicts=result.get("policy_conflicts", []),
                over_privileged_accounts=result.get("over_privileged_accounts", []),
                security_gaps=result.get("security_gaps", []),
                recommendations=result.get("recommendations", []),
            )

        except Exception as e:
            logger.error(f"Access policy analysis failed: {e}")
            return AccessPolicyAnalysis(
                policy_id="error",
                principle_of_least_privilege=False,
                separation_of_duties=False,
                policy_conflicts=[],
                over_privileged_accounts=[],
                security_gaps=[],
                recommendations=[f"Analysis error: {e}"],
            )

    def validate_rbac_model(
        self, rbac_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate Role-Based Access Control (RBAC) model

        Args:
            rbac_config: RBAC configuration

        Returns:
            Dict: Validation results
        """
        logger.info("Validating RBAC model")

        system_message = """You are an RBAC security expert.
Validate RBAC implementations for:
- Proper role hierarchy
- Permission assignment
- Role conflicts
- Excessive permissions
- Missing permissions
- Compliance with security best practices"""

        config_str = "\n".join([f"{k}: {v}" for k, v in rbac_config.items()])

        prompt = f"""Validate this RBAC configuration:

{config_str}

Provide validation results in JSON format:
{{
    "is_valid": boolean,
    "security_score": float (0-100),
    "role_hierarchy_valid": boolean,
    "issues": [list of issues found],
    "best_practice_violations": [list of violations],
    "recommendations": [list of improvements]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "is_valid": result.get("is_valid", False),
                "security_score": result.get("security_score", 0.0),
                "role_hierarchy_valid": result.get("role_hierarchy_valid", False),
                "issues": result.get("issues", []),
                "best_practice_violations": result.get("best_practice_violations", []),
                "recommendations": result.get("recommendations", []),
            }

        except Exception as e:
            logger.error(f"RBAC validation failed: {e}")
            return {"error": str(e), "is_valid": False}

    def _get_password_pattern(self, password: str) -> str:
        """Get password pattern without revealing actual password"""
        pattern = []
        for char in password:
            if char.isupper():
                pattern.append("U")
            elif char.islower():
                pattern.append("L")
            elif char.isdigit():
                pattern.append("D")
            else:
                pattern.append("S")
        return "".join(pattern)


# Example usage
if __name__ == "__main__":
    access_control = AccessControlModule()

    # Test password strength analysis
    print("=" * 70)
    print("PASSWORD STRENGTH ANALYSIS")
    print("=" * 70)

    passwords = [
        "password123",
        "P@ssw0rd!",
        "Tr0ub4dor&3",
        "correct horse battery staple",
        "aB3$xY9#mK2@pQ7!",
    ]

    for pwd in passwords:
        result = access_control.analyze_password_strength(pwd)
        print(f"\nPassword Pattern: {access_control._get_password_pattern(pwd)}")
        print(f"Strength Level: {result.strength_level}")
        print(f"Score: {result.strength_score:.1f}/100")
        print(f"Entropy: {result.entropy_bits:.1f} bits")
        print(f"Crack Time: {result.estimated_crack_time}")
        print(f"Passes Policy: {result.passes_policy}")

    # Test authentication mechanism analysis
    print("\n" + "=" * 70)
    print("AUTHENTICATION MECHANISM ANALYSIS")
    print("=" * 70)

    auth_config = {
        "method": "password + TOTP",
        "password_policy": {
            "min_length": 12,
            "complexity": "required",
            "expiry_days": 90,
        },
        "mfa": "TOTP required for all users",
        "session_timeout": 30,
        "brute_force_protection": "account lockout after 5 attempts",
        "password_reset": "email verification required",
    }

    auth_result = access_control.analyze_authentication_mechanism(auth_config)
    print(f"Auth Method: {auth_result.auth_method}")
    print(f"Security Score: {auth_result.security_score:.1f}/100")
    print(f"MFA Enabled: {auth_result.mfa_enabled}")
    print(f"Session Management: {auth_result.session_management}")
    print(f"Compliance:")
    for standard, compliant in auth_result.compliance.items():
        print(f"  - {standard}: {compliant}")

    # Test access policy analysis
    print("\n" + "=" * 70)
    print("ACCESS CONTROL POLICY ANALYSIS")
    print("=" * 70)

    policy = {
        "name": "Corporate Access Policy",
        "default_deny": True,
        "audit_logging": True,
        "review_period": "quarterly",
    }

    roles = [
        {"role": "admin", "permissions": ["read", "write", "delete", "admin"]},
        {"role": "developer", "permissions": ["read", "write"]},
        {"role": "viewer", "permissions": ["read"]},
    ]

    policy_result = access_control.analyze_access_policy(policy, roles)
    print(f"Policy ID: {policy_result.policy_id}")
    print(f"Least Privilege: {policy_result.principle_of_least_privilege}")
    print(f"Separation of Duties: {policy_result.separation_of_duties}")
    print(f"Security Gaps: {len(policy_result.security_gaps)}")
    print(f"Over-privileged Accounts: {len(policy_result.over_privileged_accounts)}")

    # Test RBAC validation
    print("\n" + "=" * 70)
    print("RBAC MODEL VALIDATION")
    print("=" * 70)

    rbac_config = {
        "roles": {
            "admin": {"inherits": [], "permissions": ["*"]},
            "manager": {"inherits": ["user"], "permissions": ["manage_team"]},
            "user": {"inherits": [], "permissions": ["read", "write_own"]},
        },
        "users": {"alice": "admin", "bob": "manager", "charlie": "user"},
    }

    rbac_result = access_control.validate_rbac_model(rbac_config)
    print(f"Is Valid: {rbac_result['is_valid']}")
    print(f"Security Score: {rbac_result['security_score']:.1f}/100")
    print(f"Role Hierarchy Valid: {rbac_result['role_hierarchy_valid']}")
    print(f"Issues Found: {len(rbac_result['issues'])}")
