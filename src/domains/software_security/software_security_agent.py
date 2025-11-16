"""
Software Security Agent
Coordinates all software security modules for comprehensive code analysis
"""

from typing import Dict, Any, List, Optional
import pandas as pd

from .vulnerability_detection import VulnerabilityDetectionModule, Language
from .vulnerability_repair import VulnerabilityRepairModule
from .bug_detection import BugDetectionModule
from .bug_repair import BugRepairModule
from .program_fuzzing import ProgramFuzzingModule
from .reverse_engineering import ReverseEngineeringModule
from .malware_detection import MalwareDetectionModule
from .system_log_analysis import SystemLogAnalysisModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class SoftwareSecurityAgent:
    """
    Software Security Agent
    Coordinates vulnerability detection, bug analysis, fuzzing, reverse engineering,
    malware detection, and log analysis
    """

    def __init__(self):
        """Initialize Software Security Agent"""
        self.config = get_config()

        # Initialize all modules
        self.vuln_detector = VulnerabilityDetectionModule()
        self.vuln_repairer = VulnerabilityRepairModule()
        self.bug_detector = BugDetectionModule()
        self.bug_repairer = BugRepairModule()
        self.fuzzer = ProgramFuzzingModule()
        self.reverse_engineer = ReverseEngineeringModule()
        self.malware_detector = MalwareDetectionModule()
        self.log_analyzer = SystemLogAnalysisModule()

        logger.info("Software Security Agent initialized with all 8 modules")

    def comprehensive_code_audit(
        self,
        code: str,
        language: Language,
        filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security audit of code

        Args:
            code: Source code to analyze
            language: Programming language
            filename: Optional filename

        Returns:
            Dict: Complete audit results
        """
        logger.info(f"Starting comprehensive code audit for {filename or 'code'}")

        results = {
            "filename": filename,
            "language": language.value,
            "modules_executed": [],
        }

        try:
            # 1. Vulnerability Detection
            logger.info("Phase 1: Vulnerability Detection")
            vuln_report = self.vuln_detector.scan_code(code, language, filename)
            results["vulnerabilities"] = {
                "total": vuln_report.total_vulnerabilities,
                "critical": vuln_report.critical_count,
                "high": vuln_report.high_count,
                "medium": vuln_report.medium_count,
                "low": vuln_report.low_count,
                "details": [
                    {
                        "id": v.vuln_id,
                        "name": v.name,
                        "severity": v.severity.value,
                        "cwe": v.cwe_id,
                        "line": v.location["line_start"]
                    }
                    for v in vuln_report.vulnerabilities[:5]  # Top 5
                ]
            }
            results["modules_executed"].append("vulnerability_detection")

            # 2. Bug Detection
            logger.info("Phase 2: Bug Detection")
            bug_report = self.bug_detector.detect_bugs(code, language, filename)
            results["bugs"] = {
                "total": bug_report.total_bugs,
                "code_quality_score": bug_report.code_quality_score,
                "details": [
                    {
                        "id": b.bug_id,
                        "name": b.name,
                        "type": b.bug_type.value,
                        "severity": b.severity
                    }
                    for b in bug_report.bugs[:5]  # Top 5
                ]
            }
            results["modules_executed"].append("bug_detection")

            # 3. CWE Detection
            logger.info("Phase 3: CWE Pattern Detection")
            cwe_list = self.vuln_detector.detect_cwe(code, language)
            results["cwe_patterns"] = cwe_list
            results["modules_executed"].append("cwe_detection")

            # 4. Code Quality Analysis
            logger.info("Phase 4: Code Quality Analysis")
            code_smells = self.bug_detector.find_code_smells(code, language)
            results["code_smells"] = {
                "total": len(code_smells),
                "smells": code_smells[:5]  # Top 5
            }
            results["modules_executed"].append("code_quality")

            # 5. Generate Summary
            results["summary"] = self._generate_audit_summary(results)
            results["risk_score"] = self._calculate_risk_score(results)

            logger.info(
                f"Comprehensive audit complete. "
                f"Risk Score: {results['risk_score']}/100"
            )
            return results

        except Exception as e:
            logger.error(f"Comprehensive audit failed: {e}")
            results["error"] = str(e)
            return results

    def fix_vulnerabilities(
        self,
        code: str,
        language: Language
    ) -> Dict[str, Any]:
        """
        Detect and fix vulnerabilities in code

        Args:
            code: Source code
            language: Programming language

        Returns:
            Dict: Repair results
        """
        logger.info("Detecting and fixing vulnerabilities")

        # Detect vulnerabilities
        vuln_report = self.vuln_detector.scan_code(code, language)

        if vuln_report.total_vulnerabilities == 0:
            return {
                "vulnerabilities_found": 0,
                "message": "No vulnerabilities detected"
            }

        # Repair vulnerabilities
        repair_report = self.vuln_repairer.repair_multiple_vulnerabilities(
            vuln_report.vulnerabilities,
            code,
            language
        )

        return {
            "vulnerabilities_found": vuln_report.total_vulnerabilities,
            "repaired": repair_report.repaired_count,
            "failed": repair_report.failed_count,
            "patches": [
                {
                    "patch_id": p.patch_id,
                    "vulnerability_id": p.vulnerability_id,
                    "confidence": p.confidence,
                    "has_side_effects": len(p.side_effects) > 0
                }
                for p in repair_report.patches
            ],
            "summary": repair_report.summary
        }

    def analyze_malware(self, file_content: str, file_type: str = "unknown") -> Dict[str, Any]:
        """
        Analyze file for malware

        Args:
            file_content: File content to analyze
            file_type: Type of file

        Returns:
            Dict: Malware analysis results
        """
        logger.info(f"Analyzing {file_type} for malware")

        report = self.malware_detector.scan_file(file_content, file_type)

        return {
            "is_malware": report.is_malware,
            "confidence": report.confidence,
            "severity": report.severity,
            "malware_types": [mt.value for mt in report.malware_types],
            "behaviors": report.behaviors,
            "iocs": report.iocs,
            "recommendations": report.recommendations
        }

    def analyze_system_logs(self, log_content: str) -> Dict[str, Any]:
        """
        Analyze system logs for anomalies

        Args:
            log_content: Log file content

        Returns:
            Dict: Log analysis results
        """
        logger.info("Analyzing system logs")

        logs_df = self.log_analyzer.parse_logs(log_content)
        report = self.log_analyzer.detect_anomalies(logs_df)

        return {
            "total_logs": report.total_logs,
            "anomalies_found": report.anomalies_found,
            "summary": report.summary,
            "trends": report.trends,
            "critical_anomalies": [
                {
                    "id": a.anomaly_id,
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "description": a.description,
                    "root_cause": a.root_cause
                }
                for a in report.anomalies
                if a.severity in ["CRITICAL", "HIGH"]
            ]
        }

    def reverse_engineer_binary(self, binary_description: str) -> Dict[str, Any]:
        """
        Reverse engineer binary code

        Args:
            binary_description: Binary/assembly code

        Returns:
            Dict: Decompilation results
        """
        logger.info("Reverse engineering binary")

        decomp = self.reverse_engineer.decompile_binary(binary_description)

        return {
            "language": decomp.language,
            "code": decomp.code,
            "confidence": decomp.confidence,
            "functions": decomp.functions,
            "analysis": decomp.analysis
        }

    def generate_fuzz_tests(
        self,
        function_signature: str,
        language: Language,
        count: int = 10
    ) -> Dict[str, Any]:
        """
        Generate fuzz test cases

        Args:
            function_signature: Function to test
            language: Programming language
            count: Number of test cases

        Returns:
            Dict: Generated test cases
        """
        logger.info(f"Generating {count} fuzz tests")

        test_cases = self.fuzzer.generate_test_cases(function_signature, language, count)

        return {
            "total_tests": len(test_cases),
            "test_cases": [
                {
                    "id": tc.test_id,
                    "type": tc.test_type,
                    "input": str(tc.input_data),
                    "expected": tc.expected_behavior
                }
                for tc in test_cases
            ]
        }

    def _generate_audit_summary(self, results: Dict[str, Any]) -> str:
        """Generate human-readable audit summary"""
        vuln_count = results.get("vulnerabilities", {}).get("total", 0)
        bug_count = results.get("bugs", {}).get("total", 0)
        quality_score = results.get("bugs", {}).get("code_quality_score", 0)

        summary = f"""Security Audit Summary:
- Vulnerabilities Found: {vuln_count}
- Bugs Detected: {bug_count}
- Code Quality Score: {quality_score:.1f}/100
- CWE Patterns: {len(results.get('cwe_patterns', []))}
- Code Smells: {results.get('code_smells', {}).get('total', 0)}

"""
        if vuln_count > 0:
            critical = results["vulnerabilities"]["critical"]
            high = results["vulnerabilities"]["high"]
            summary += f"⚠️ CRITICAL: {critical} critical, {high} high severity vulnerabilities found!\n"

        if quality_score < 50:
            summary += "⚠️ Code quality needs significant improvement.\n"

        return summary

    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-100, higher is riskier)"""
        score = 0.0

        # Vulnerability contribution (max 60 points)
        vuln_data = results.get("vulnerabilities", {})
        score += vuln_data.get("critical", 0) * 15
        score += vuln_data.get("high", 0) * 10
        score += vuln_data.get("medium", 0) * 5
        score += vuln_data.get("low", 0) * 2

        # Bug contribution (max 20 points)
        bug_count = results.get("bugs", {}).get("total", 0)
        score += min(bug_count * 2, 20)

        # Code quality (max 20 points)
        quality_score = results.get("bugs", {}).get("code_quality_score", 100)
        score += (100 - quality_score) / 5  # Inverse of quality

        return min(score, 100.0)

    def get_agent_status(self) -> Dict[str, Any]:
        """Get agent status and capabilities"""
        return {
            "agent_name": "Software & System Security Agent",
            "status": "active",
            "modules": {
                "vulnerability_detection": "active",
                "vulnerability_repair": "active",
                "bug_detection": "active",
                "bug_repair": "active",
                "program_fuzzing": "active",
                "reverse_engineering": "active",
                "malware_detection": "active",
                "system_log_analysis": "active",
            },
            "capabilities": [
                "Vulnerability detection and repair (CWE mapping)",
                "Bug detection and automated fixing",
                "Fuzz test generation",
                "Binary decompilation and reverse engineering",
                "Malware detection and analysis",
                "System log anomaly detection",
                "Code quality assessment",
                "Dependency vulnerability scanning"
            ],
            "supported_languages": [lang.value for lang in Language]
        }


# Example usage
if __name__ == "__main__":
    agent = SoftwareSecurityAgent()

    # Test comprehensive audit
    print("=" * 80)
    print("SOFTWARE SECURITY AGENT - COMPREHENSIVE AUDIT")
    print("=" * 80)

    vulnerable_code = """
import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query).fetchone()
    return result

def calculate_average(numbers):
    # Division by zero bug
    return sum(numbers) / len(numbers)

def process_file(filename):
    # Resource leak
    f = open(filename)
    data = f.read()
    return data

password = "admin123"  # Hardcoded credential
API_KEY = "sk-1234567890"  # Hardcoded API key
"""

    try:
        status = agent.get_agent_status()
        print(f"\nAgent: {status['agent_name']}")
        print(f"Status: {status['status']}")
        print(f"Modules: {len(status['modules'])}")

        print("\n" + "=" * 80)
        print("RUNNING COMPREHENSIVE AUDIT...")
        print("=" * 80)

        results = agent.comprehensive_code_audit(
            vulnerable_code,
            Language.PYTHON,
            filename="app.py"
        )

        print(f"\n{results['summary']}")
        print(f"Overall Risk Score: {results['risk_score']:.1f}/100")

        print(f"\nModules Executed: {', '.join(results['modules_executed'])}")

        if results.get("vulnerabilities"):
            vuln = results["vulnerabilities"]
            print(f"\n📊 Vulnerabilities: {vuln['total']}")
            print(f"   Critical: {vuln['critical']}, High: {vuln['high']}, "
                  f"Medium: {vuln['medium']}, Low: {vuln['low']}")

            if vuln["details"]:
                print(f"\n   Top Vulnerabilities:")
                for v in vuln["details"][:3]:
                    print(f"   - [{v['severity']}] {v['name']} ({v['cwe']}) at line {v['line']}")

        if results.get("bugs"):
            bugs = results["bugs"]
            print(f"\n🐛 Bugs: {bugs['total']}")
            print(f"   Code Quality Score: {bugs['code_quality_score']:.1f}/100")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
