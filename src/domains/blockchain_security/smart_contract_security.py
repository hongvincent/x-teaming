"""
Smart Contract Security Module
Audits Solidity smart contracts for vulnerabilities
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityFinding:
    """Smart contract vulnerability finding"""

    vulnerability_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    affected_code: str
    line_numbers: List[int]
    remediation: str
    references: List[str]


@dataclass
class SmartContractAudit:
    """Complete smart contract audit report"""

    contract_name: str
    audit_id: str
    timestamp: str
    security_score: float  # 0-100
    vulnerabilities: List[VulnerabilityFinding]
    best_practices: List[str]
    gas_optimization: List[str]
    recommendations: List[str]
    overall_risk: str


@dataclass
class SecurityPattern:
    """Security pattern analysis"""

    pattern_name: str
    implemented: bool
    description: str
    recommendation: str


class SmartContractSecurityModule:
    """
    Smart Contract Security Module
    Audits Solidity smart contracts for security vulnerabilities
    """

    def __init__(self):
        """Initialize smart contract security module"""
        self.llm_client = LLMClient()
        logger.info("Smart Contract Security Module initialized")

    def audit_contract(
        self, contract_code: str, contract_name: str = "Contract"
    ) -> SmartContractAudit:
        """
        Perform comprehensive security audit of smart contract

        Args:
            contract_code: Solidity contract source code
            contract_name: Name of the contract

        Returns:
            SmartContractAudit: Complete audit report
        """
        logger.info(f"Auditing smart contract: {contract_name}")

        system_message = """You are a smart contract security auditor expert in Solidity.
Identify vulnerabilities including:
- Reentrancy attacks
- Integer overflow/underflow
- Access control issues
- Unchecked return values
- Front-running vulnerabilities
- Timestamp dependence
- Delegatecall to untrusted contract
- tx.origin authentication
- Denial of Service
- Unprotected self-destruct
- Improper randomness
- Flash loan attacks"""

        prompt = f"""Audit this Solidity smart contract for security vulnerabilities:

Contract Name: {contract_name}

```solidity
{contract_code[:3000]}
```

Provide comprehensive security audit in JSON format:
{{
    "security_score": float (0-100),
    "overall_risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "vulnerabilities": [
        {{
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
            "category": "vulnerability category (e.g., reentrancy, access_control)",
            "title": "brief title",
            "description": "detailed description",
            "affected_code": "relevant code snippet",
            "line_numbers": [affected line numbers],
            "remediation": "how to fix",
            "references": ["SWC-XXX", "reference links"]
        }}
    ],
    "best_practices": [list of best practices violated or followed],
    "gas_optimization": [list of gas optimization suggestions],
    "recommendations": [list of overall recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            audit_id = f"audit_{datetime.now().timestamp()}"

            # Build vulnerabilities list
            vulnerabilities = []
            for vuln in result.get("vulnerabilities", []):
                vulnerabilities.append(
                    VulnerabilityFinding(
                        vulnerability_id=f"vuln_{len(vulnerabilities)}",
                        severity=vuln.get("severity", "MEDIUM"),
                        category=vuln.get("category", "unknown"),
                        title=vuln.get("title", ""),
                        description=vuln.get("description", ""),
                        affected_code=vuln.get("affected_code", ""),
                        line_numbers=vuln.get("line_numbers", []),
                        remediation=vuln.get("remediation", ""),
                        references=vuln.get("references", []),
                    )
                )

            return SmartContractAudit(
                contract_name=contract_name,
                audit_id=audit_id,
                timestamp=datetime.now().isoformat(),
                security_score=result.get("security_score", 0.0),
                vulnerabilities=vulnerabilities,
                best_practices=result.get("best_practices", []),
                gas_optimization=result.get("gas_optimization", []),
                recommendations=result.get("recommendations", []),
                overall_risk=result.get("overall_risk", "UNKNOWN"),
            )

        except Exception as e:
            logger.error(f"Smart contract audit failed: {e}")
            return SmartContractAudit(
                contract_name=contract_name,
                audit_id="error",
                timestamp=datetime.now().isoformat(),
                security_score=0.0,
                vulnerabilities=[],
                best_practices=[],
                gas_optimization=[],
                recommendations=[f"Audit error: {e}"],
                overall_risk="UNKNOWN",
            )

    def detect_reentrancy(self, contract_code: str) -> Dict[str, Any]:
        """
        Detect reentrancy vulnerabilities

        Args:
            contract_code: Contract source code

        Returns:
            Dict: Reentrancy analysis
        """
        logger.info("Analyzing for reentrancy vulnerabilities")

        system_message = """You are a reentrancy vulnerability detection expert.
Identify patterns that could lead to reentrancy attacks:
- External calls before state updates
- Check-effects-interactions pattern violations
- Missing reentrancy guards
- Unsafe use of call, delegatecall, or send"""

        prompt = f"""Analyze this contract for reentrancy vulnerabilities:

```solidity
{contract_code[:2000]}
```

Provide analysis in JSON format:
{{
    "vulnerable": boolean,
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
    "vulnerable_functions": [list of function names],
    "attack_scenario": "description of potential attack",
    "remediation": "how to fix",
    "uses_reentrancy_guard": boolean
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "vulnerable": result.get("vulnerable", False),
                "severity": result.get("severity", "NONE"),
                "vulnerable_functions": result.get("vulnerable_functions", []),
                "attack_scenario": result.get("attack_scenario", ""),
                "remediation": result.get("remediation", ""),
                "uses_reentrancy_guard": result.get("uses_reentrancy_guard", False),
            }

        except Exception as e:
            logger.error(f"Reentrancy detection failed: {e}")
            return {"error": str(e), "vulnerable": False}

    def analyze_access_control(self, contract_code: str) -> Dict[str, Any]:
        """
        Analyze access control mechanisms

        Args:
            contract_code: Contract source code

        Returns:
            Dict: Access control analysis
        """
        logger.info("Analyzing access control")

        system_message = """You are an access control security expert for smart contracts.
Identify access control issues:
- Missing access modifiers
- Incorrect use of tx.origin
- Unprotected sensitive functions
- Role-based access control implementation
- Owner privilege risks"""

        prompt = f"""Analyze access control in this contract:

```solidity
{contract_code[:2000]}
```

Provide analysis in JSON format:
{{
    "access_control_implemented": boolean,
    "vulnerabilities": [list of access control vulnerabilities],
    "unprotected_functions": [list of sensitive functions without protection],
    "uses_ownable": boolean,
    "uses_role_based": boolean,
    "centralization_risk": "HIGH" | "MEDIUM" | "LOW",
    "recommendations": [list of recommendations]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "access_control_implemented": result.get(
                    "access_control_implemented", False
                ),
                "vulnerabilities": result.get("vulnerabilities", []),
                "unprotected_functions": result.get("unprotected_functions", []),
                "uses_ownable": result.get("uses_ownable", False),
                "uses_role_based": result.get("uses_role_based", False),
                "centralization_risk": result.get("centralization_risk", "UNKNOWN"),
                "recommendations": result.get("recommendations", []),
            }

        except Exception as e:
            logger.error(f"Access control analysis failed: {e}")
            return {"error": str(e), "access_control_implemented": False}

    def check_security_patterns(self, contract_code: str) -> List[SecurityPattern]:
        """
        Check implementation of security patterns

        Args:
            contract_code: Contract source code

        Returns:
            List[SecurityPattern]: Security pattern analysis
        """
        logger.info("Checking security patterns")

        system_message = """You are a smart contract security patterns expert.
Check implementation of security best practices:
- Checks-Effects-Interactions pattern
- Pull over Push pattern
- Circuit breaker / Emergency stop
- Rate limiting
- Upgrade patterns (proxy, eternal storage)"""

        prompt = f"""Analyze security patterns in this contract:

```solidity
{contract_code[:2000]}
```

Provide pattern analysis in JSON format:
{{
    "patterns": [
        {{
            "pattern_name": "pattern name",
            "implemented": boolean,
            "description": "how it's implemented or missing",
            "recommendation": "recommendation"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            patterns = []
            for pattern in result.get("patterns", []):
                patterns.append(
                    SecurityPattern(
                        pattern_name=pattern.get("pattern_name", ""),
                        implemented=pattern.get("implemented", False),
                        description=pattern.get("description", ""),
                        recommendation=pattern.get("recommendation", ""),
                    )
                )

            return patterns

        except Exception as e:
            logger.error(f"Security pattern check failed: {e}")
            return []


# Example usage
if __name__ == "__main__":
    auditor = SmartContractSecurityModule()

    # Test smart contract audit
    print("=" * 70)
    print("SMART CONTRACT SECURITY AUDIT")
    print("=" * 70)

    vulnerable_contract = """
    pragma solidity ^0.8.0;

    contract VulnerableBank {
        mapping(address => uint256) public balances;

        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");

            // Vulnerable to reentrancy - external call before state update
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");

            balances[msg.sender] -= amount;
        }

        // Unprotected function
        function emergencyWithdraw() public {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """

    audit = auditor.audit_contract(vulnerable_contract, "VulnerableBank")
    print(f"Contract: {audit.contract_name}")
    print(f"Security Score: {audit.security_score:.1f}/100")
    print(f"Overall Risk: {audit.overall_risk}")
    print(f"Vulnerabilities Found: {len(audit.vulnerabilities)}")

    print("\nVulnerabilities:")
    for vuln in audit.vulnerabilities[:3]:
        print(f"\n  [{vuln.severity}] {vuln.title}")
        print(f"  Category: {vuln.category}")
        print(f"  {vuln.description[:100]}...")

    # Test reentrancy detection
    print("\n" + "=" * 70)
    print("REENTRANCY VULNERABILITY DETECTION")
    print("=" * 70)

    reentrancy_result = auditor.detect_reentrancy(vulnerable_contract)
    print(f"Vulnerable: {reentrancy_result['vulnerable']}")
    print(f"Severity: {reentrancy_result['severity']}")
    print(f"Vulnerable Functions: {', '.join(reentrancy_result['vulnerable_functions'])}")
    print(f"Uses Reentrancy Guard: {reentrancy_result['uses_reentrancy_guard']}")

    # Test access control analysis
    print("\n" + "=" * 70)
    print("ACCESS CONTROL ANALYSIS")
    print("=" * 70)

    access_result = auditor.analyze_access_control(vulnerable_contract)
    print(f"Access Control Implemented: {access_result['access_control_implemented']}")
    print(f"Centralization Risk: {access_result['centralization_risk']}")
    print(f"Unprotected Functions: {len(access_result['unprotected_functions'])}")
    print(f"Vulnerabilities: {len(access_result['vulnerabilities'])}")

    # Test security patterns
    print("\n" + "=" * 70)
    print("SECURITY PATTERNS ANALYSIS")
    print("=" * 70)

    patterns = auditor.check_security_patterns(vulnerable_contract)
    for pattern in patterns[:3]:
        print(f"\nPattern: {pattern.pattern_name}")
        print(f"Implemented: {pattern.implemented}")
        print(f"Recommendation: {pattern.recommendation[:80]}...")
