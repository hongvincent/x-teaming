"""
Penetration Testing Module
Automated security testing and vulnerability exploitation
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ReconData:
    """Reconnaissance data"""

    target: str
    open_ports: List[int]
    services: Dict[int, str]
    os_detection: str
    vulnerabilities: List[str]
    subdomains: List[str]
    technologies: List[str]


@dataclass
class Exploit:
    """Exploit information"""

    name: str
    cve_id: str
    description: str
    exploit_code: str
    requirements: List[str]
    success_probability: float
    impact: str


@dataclass
class EscalationPath:
    """Privilege escalation path"""

    current_privilege: str
    target_privilege: str
    steps: List[Dict[str, str]]
    tools_required: List[str]
    difficulty: str
    estimated_time: str


class PenetrationTestingModule:
    """
    Automated Penetration Testing Module
    Inspired by PentestGPT from the paper
    """

    def __init__(self):
        """Initialize penetration testing module"""
        self.llm_client = LLMClient()
        logger.info("Penetration Testing Module initialized")

    def perform_reconnaissance(
        self, target: str, scope: str = "standard"
    ) -> ReconData:
        """
        Perform reconnaissance on target

        Args:
            target: Target IP/domain
            scope: Scope of recon (minimal, standard, comprehensive)

        Returns:
            ReconData: Reconnaissance results
        """
        logger.info(f"Performing reconnaissance on {target} (scope: {scope})")

        system_message = """You are a professional penetration tester performing reconnaissance.
Identify open ports, services, potential vulnerabilities, and attack surfaces.
Follow ethical hacking guidelines and stay within scope."""

        prompt = f"""Perform {scope} reconnaissance on target: {target}

Provide detailed reconnaissance report in JSON format:
{{
    "open_ports": [list of likely open ports based on common services],
    "services": {{"port": "service_name_and_version"}},
    "os_detection": "detected or likely operating system",
    "vulnerabilities": ["list of potential vulnerabilities to investigate"],
    "subdomains": ["list of possible subdomains to enumerate"],
    "technologies": ["detected or likely technologies in use"]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            recon = ReconData(
                target=target,
                open_ports=result.get("open_ports", []),
                services=result.get("services", {}),
                os_detection=result.get("os_detection", "Unknown"),
                vulnerabilities=result.get("vulnerabilities", []),
                subdomains=result.get("subdomains", []),
                technologies=result.get("technologies", []),
            )

            logger.info(
                f"Reconnaissance complete: {len(recon.open_ports)} ports, {len(recon.vulnerabilities)} potential vulnerabilities"
            )
            return recon

        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            return ReconData(
                target=target,
                open_ports=[],
                services={},
                os_detection="Unknown",
                vulnerabilities=[],
                subdomains=[],
                technologies=[],
            )

    def generate_exploit(
        self, vulnerability: str, target_info: Optional[Dict[str, Any]] = None
    ) -> Exploit:
        """
        Generate exploit for vulnerability

        Args:
            vulnerability: Vulnerability description or CVE
            target_info: Information about target system

        Returns:
            Exploit: Generated exploit
        """
        logger.info(f"Generating exploit for vulnerability: {vulnerability}")

        system_message = """You are a security researcher developing proof-of-concept exploits.
Generate educational exploit code with proper safety warnings and ethical considerations.
Include detailed explanations and prerequisites."""

        target_str = (
            "\n".join([f"{k}: {v}" for k, v in target_info.items()])
            if target_info
            else "No specific target information"
        )

        prompt = f"""Generate a proof-of-concept exploit for this vulnerability:

Vulnerability: {vulnerability}

Target Information:
{target_str}

Provide exploit details in JSON format:
{{
    "name": "exploit name",
    "cve_id": "CVE ID if applicable",
    "description": "detailed vulnerability description",
    "exploit_code": "proof-of-concept code (Python preferred)",
    "requirements": ["list of prerequisites"],
    "success_probability": float (0-1),
    "impact": "potential impact description"
}}

IMPORTANT: This is for educational and authorized testing only."""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message, max_tokens=2000
            )

            exploit = Exploit(
                name=result.get("name", "Unknown Exploit"),
                cve_id=result.get("cve_id", "N/A"),
                description=result.get("description", ""),
                exploit_code=result.get("exploit_code", ""),
                requirements=result.get("requirements", []),
                success_probability=result.get("success_probability", 0.0),
                impact=result.get("impact", ""),
            )

            logger.info(f"Exploit generated: {exploit.name}")
            return exploit

        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            raise

    def attempt_privilege_escalation(
        self, current_access: str, target_system: str
    ) -> EscalationPath:
        """
        Plan privilege escalation path

        Args:
            current_access: Current privilege level
            target_system: Target operating system

        Returns:
            EscalationPath: Privilege escalation plan
        """
        logger.info(
            f"Planning privilege escalation from {current_access} on {target_system}"
        )

        system_message = """You are a penetration tester specializing in privilege escalation.
Provide step-by-step escalation paths with specific commands and techniques.
Consider Linux, Windows, and various privilege escalation vectors."""

        prompt = f"""Plan a privilege escalation from {current_access} to root/administrator on {target_system}

Provide detailed escalation path in JSON format:
{{
    "target_privilege": "root" or "administrator",
    "steps": [
        {{
            "step_number": 1,
            "action": "description of action",
            "command": "specific command to execute",
            "expected_result": "what should happen"
        }}
    ],
    "tools_required": ["list of tools needed"],
    "difficulty": "easy|medium|hard|very_hard",
    "estimated_time": "estimated time to complete"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            escalation = EscalationPath(
                current_privilege=current_access,
                target_privilege=result.get("target_privilege", "root"),
                steps=result.get("steps", []),
                tools_required=result.get("tools_required", []),
                difficulty=result.get("difficulty", "medium"),
                estimated_time=result.get("estimated_time", "Unknown"),
            )

            logger.info(f"Escalation path created with {len(escalation.steps)} steps")
            return escalation

        except Exception as e:
            logger.error(f"Privilege escalation planning failed: {e}")
            raise

    def generate_pentest_report(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        scope: str,
    ) -> str:
        """
        Generate comprehensive penetration testing report

        Args:
            findings: List of security findings
            target: Target system
            scope: Testing scope

        Returns:
            str: Formatted penetration testing report
        """
        logger.info("Generating penetration testing report")

        system_message = """You are a professional penetration tester writing a comprehensive report.
Create clear, actionable reports with executive summaries, technical details,
risk ratings, and remediation recommendations."""

        findings_str = "\n".join(
            [
                f"- {f.get('title', 'Finding')}: {f.get('description', '')}"
                for f in findings
            ]
        )

        prompt = f"""Generate a comprehensive penetration testing report:

Target: {target}
Scope: {scope}

Findings:
{findings_str}

Create a professional report with:
1. Executive Summary
2. Scope and Methodology
3. Findings Summary Table
4. Detailed Technical Findings
5. Risk Assessment
6. Remediation Recommendations
7. Conclusion

Format in clear Markdown."""

        try:
            report = self.llm_client.complete(
                prompt, system_message=system_message, max_tokens=3000
            )
            logger.info("Penetration testing report generated")
            return report

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return f"Error generating report: {e}"

    def suggest_attack_vectors(
        self, recon_data: ReconData
    ) -> List[Dict[str, Any]]:
        """
        Suggest potential attack vectors based on reconnaissance

        Args:
            recon_data: Reconnaissance data

        Returns:
            List[Dict]: Suggested attack vectors
        """
        logger.info("Analyzing attack vectors")

        system_message = """You are a penetration tester analyzing attack surface.
Suggest specific attack vectors based on discovered services and vulnerabilities.
Prioritize by likelihood of success and potential impact."""

        recon_summary = f"""
Target: {recon_data.target}
Open Ports: {', '.join(map(str, recon_data.open_ports))}
Services: {recon_data.services}
OS: {recon_data.os_detection}
Vulnerabilities: {', '.join(recon_data.vulnerabilities)}
Technologies: {', '.join(recon_data.technologies)}
"""

        prompt = f"""Based on this reconnaissance data, suggest attack vectors:

{recon_summary}

Provide prioritized attack vectors in JSON format:
{{
    "vectors": [
        {{
            "name": "attack vector name",
            "target_service": "which service to target",
            "technique": "specific technique to use",
            "tools": ["required tools"],
            "priority": "high|medium|low",
            "difficulty": "easy|medium|hard",
            "expected_outcome": "what this attack achieves"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )
            vectors = result.get("vectors", [])
            logger.info(f"Identified {len(vectors)} attack vectors")
            return vectors

        except Exception as e:
            logger.error(f"Attack vector analysis failed: {e}")
            return []


# Example usage
if __name__ == "__main__":
    pentest = PenetrationTestingModule()

    # Test reconnaissance
    print("=" * 50)
    print("Reconnaissance")
    print("=" * 50)

    recon = pentest.perform_reconnaissance("192.168.1.100", scope="standard")
    print(f"Target: {recon.target}")
    print(f"OS: {recon.os_detection}")
    print(f"Open Ports: {recon.open_ports}")
    print(f"Services: {recon.services}")
    print(f"Vulnerabilities: {len(recon.vulnerabilities)}")

    # Test exploit generation
    print("\n" + "=" * 50)
    print("Exploit Generation")
    print("=" * 50)

    if recon.vulnerabilities:
        exploit = pentest.generate_exploit(
            recon.vulnerabilities[0], {"os": recon.os_detection}
        )
        print(f"Exploit: {exploit.name}")
        print(f"CVE: {exploit.cve_id}")
        print(f"Success Probability: {exploit.success_probability:.2f}")
        print(f"Impact: {exploit.impact}")

    # Test privilege escalation
    print("\n" + "=" * 50)
    print("Privilege Escalation")
    print("=" * 50)

    escalation = pentest.attempt_privilege_escalation(
        "www-data", "Ubuntu 20.04 Linux"
    )
    print(f"From: {escalation.current_privilege}")
    print(f"To: {escalation.target_privilege}")
    print(f"Steps: {len(escalation.steps)}")
    print(f"Difficulty: {escalation.difficulty}")
    print(f"Estimated Time: {escalation.estimated_time}")

    # Test attack vector suggestions
    print("\n" + "=" * 50)
    print("Attack Vector Analysis")
    print("=" * 50)

    vectors = pentest.suggest_attack_vectors(recon)
    for i, vector in enumerate(vectors, 1):
        print(f"\n{i}. {vector.get('name', 'Unknown')}")
        print(f"   Priority: {vector.get('priority', 'N/A')}")
        print(f"   Difficulty: {vector.get('difficulty', 'N/A')}")
        print(f"   Outcome: {vector.get('expected_outcome', 'N/A')}")
