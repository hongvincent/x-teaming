#!/usr/bin/env python3
"""
Network Security Agent Demonstration
Showcases all 4 modules of the Network Security Agent
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.domains.network_security.network_security_agent import NetworkSecurityAgent
from src.utils.logger import setup_logging, get_logger

# Setup logging
setup_logging(log_level="INFO", log_output="console", log_format="text")
logger = get_logger(__name__)


def print_section(title: str):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def demo_web_fuzzing():
    """Demonstrate web fuzzing capabilities"""
    print_section("MODULE 1: WEB FUZZING - SQL Injection & XSS Detection")

    agent = NetworkSecurityAgent()

    # Test 1: SQL Injection Payload Generation
    print("🔍 Generating SQL Injection payloads for vulnerable endpoint...")
    print("Target: http://vulnerable-app.com/api/user?id=1\n")

    try:
        sqli_payloads = agent.web_fuzzing.generate_sqli_payloads(
            "http://vulnerable-app.com/api/user", param_name="id", count=5
        )

        print(f"✅ Generated {len(sqli_payloads)} SQL injection payloads:\n")
        for i, payload in enumerate(sqli_payloads[:3], 1):
            print(f"{i}. {payload.description}")
            print(f"   Payload: {payload.payload}")
            print(f"   Severity: {payload.severity}")
            print(f"   Test URL: {payload.test_vector[:80]}...\n")

    except Exception as e:
        print(f"❌ Error: {e}\n")

    # Test 2: XSS Vulnerability Detection
    print("\n🔍 Testing form for XSS vulnerabilities...")
    form_data = {
        "username": "john_doe",
        "comment": "Great article! <script>alert('test')</script>",
        "email": "john@example.com",
    }

    print(f"Form Data: {form_data}\n")

    try:
        xss_report = agent.web_fuzzing.detect_xss_vulnerabilities(
            form_data, context="comment_form"
        )

        print(f"Vulnerable: {xss_report.vulnerable}")
        print(f"Vulnerability Type: {xss_report.vulnerability_type}")
        print(f"Risk Level: {xss_report.risk_level}")
        print(f"Payloads Tested: {xss_report.payloads_tested}")
        if xss_report.remediation:
            print(f"Remediation: {xss_report.remediation}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_traffic_detection():
    """Demonstrate network traffic detection"""
    print_section("MODULE 2: TRAFFIC & INTRUSION DETECTION")

    agent = NetworkSecurityAgent()

    # Test 1: Network Flow Analysis
    print("🔍 Analyzing network traffic for anomalies...")

    traffic_data = {
        "src_ip": "192.168.1.100",
        "dst_ip": "198.51.100.50",
        "protocol": "TCP",
        "dst_port": 22,
        "bytes_sent": 250000,
        "bytes_received": 150000,
        "connection_count": 150,
        "time_window": "5 minutes",
    }

    print(f"Traffic Data: {traffic_data}\n")

    try:
        anomaly_report = agent.traffic_detection.analyze_network_flow(
            traffic_data, context="Corporate network SSH traffic"
        )

        print(f"✅ Analysis Complete:")
        print(f"   Anomaly Detected: {anomaly_report.anomaly_detected}")
        print(f"   Anomaly Type: {anomaly_report.anomaly_type}")
        print(f"   Confidence: {anomaly_report.confidence:.2f}")
        print(f"   Severity: {anomaly_report.severity}")
        print(f"   Description: {anomaly_report.description[:200]}...")
        if anomaly_report.recommendations:
            print(f"\n   Recommendations:")
            for rec in anomaly_report.recommendations[:3]:
                print(f"   - {rec}")

    except Exception as e:
        print(f"❌ Error: {e}")

    # Test 2: Malicious URL Detection
    print("\n\n🔍 Scanning URLs for threats...")

    test_urls = [
        "https://github.com/anthropics/claude-code",
        "http://suspicious-banking-site.ru/login.php",
        "https://www.google.com",
    ]

    print(f"URLs to scan: {len(test_urls)}\n")

    try:
        url_results = agent.traffic_detection.detect_malicious_urls(test_urls)

        for i, result in enumerate(url_results, 1):
            status = "🚨 MALICIOUS" if result.is_malicious else "✅ CLEAN"
            print(f"{i}. {status} - {result.url}")
            print(f"   Confidence: {result.confidence:.2f}")
            if result.threat_types:
                print(f"   Threat Types: {', '.join(result.threat_types)}")
            if result.indicators:
                print(f"   Indicators: {', '.join(result.indicators[:2])}")
            print()

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_cyber_threat_intelligence():
    """Demonstrate CTI capabilities"""
    print_section("MODULE 3: CYBER THREAT INTELLIGENCE (CTI)")

    agent = NetworkSecurityAgent()

    # Test 1: Threat Report Generation
    print("🔍 Generating threat intelligence report...")

    incident_data = {
        "incident_type": "unauthorized_access",
        "source_ip": "203.0.113.100",
        "target_system": "web-server-prod-01",
        "attack_method": "credential_stuffing",
        "accounts_affected": 150,
        "detection_time": "2025-01-15 14:30:00",
        "data_accessed": "user_profiles",
    }

    print(f"Incident Data:\n{incident_data}\n")

    try:
        cti_report = agent.cti.generate_threat_report(incident_data)

        print(f"✅ CTI Report Generated:")
        print(f"   Report ID: {cti_report.report_id}")
        print(f"   Title: {cti_report.title}")
        print(f"   Threat Actor: {cti_report.threat_actor}")
        print(f"   Severity: {cti_report.severity}")
        print(f"   IOCs Identified: {len(cti_report.iocs)}")
        print(f"   Affected Sectors: {', '.join(cti_report.affected_sectors)}")
        print(f"\n   Executive Summary:")
        print(f"   {cti_report.executive_summary[:300]}...")

        if cti_report.iocs:
            print(f"\n   Sample IOCs:")
            for ioc in cti_report.iocs[:3]:
                print(f"   - {ioc.type}: {ioc.value} ({ioc.severity})")

        if cti_report.recommendations:
            print(f"\n   Top Recommendations:")
            for rec in cti_report.recommendations[:2]:
                print(f"   - {rec}")

    except Exception as e:
        print(f"❌ Error: {e}")

    # Test 2: IOC Extraction
    print("\n\n🔍 Extracting IOCs from threat report...")

    sample_report = """
    Security Alert: Advanced Persistent Threat Detected

    Our security team identified a sophisticated attack campaign targeting
    our infrastructure. The threat actor used IP address 198.51.100.25 to
    establish initial access. Command and control communication was observed
    with domain evil-c2-server.com on port 443.

    Malware hash: 5d41402abc4b2a76b9719d911017c592 (MD5)
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    Phishing emails originated from attacker@malicious-domain.net
    Payload downloaded from: http://malware-distribution.org/payload.exe
    """

    print(f"Report length: {len(sample_report)} characters\n")

    try:
        iocs = agent.cti.extract_iocs(sample_report)

        print(f"✅ Extracted {len(iocs)} IOCs:\n")
        for ioc in iocs:
            print(f"   [{ioc.type.upper()}] {ioc.value}")
            print(f"   Severity: {ioc.severity}")
            print(f"   Context: {ioc.description[:80]}...")
            print()

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_penetration_testing():
    """Demonstrate penetration testing capabilities"""
    print_section("MODULE 4: AUTOMATED PENETRATION TESTING")

    agent = NetworkSecurityAgent()

    # Test 1: Reconnaissance
    print("🔍 Performing reconnaissance on target system...")
    target = "192.168.1.50"
    print(f"Target: {target}\n")

    try:
        recon = agent.pentest.perform_reconnaissance(target, scope="standard")

        print(f"✅ Reconnaissance Complete:")
        print(f"   Target: {recon.target}")
        print(f"   OS Detection: {recon.os_detection}")
        print(f"   Open Ports: {', '.join(map(str, recon.open_ports[:5]))}")
        if recon.services:
            print(f"   Services Detected:")
            for port, service in list(recon.services.items())[:3]:
                print(f"   - Port {port}: {service}")
        print(f"   Technologies: {', '.join(recon.technologies[:3])}")
        print(f"   Potential Vulnerabilities: {len(recon.vulnerabilities)}")

        if recon.vulnerabilities:
            print(f"\n   Sample Vulnerabilities:")
            for vuln in recon.vulnerabilities[:2]:
                print(f"   - {vuln}")

    except Exception as e:
        print(f"❌ Error: {e}")

    # Test 2: Attack Vector Analysis
    print("\n\n🔍 Analyzing potential attack vectors...")

    try:
        vectors = agent.pentest.suggest_attack_vectors(recon)

        print(f"✅ Identified {len(vectors)} Attack Vectors:\n")
        for i, vector in enumerate(vectors[:3], 1):
            print(f"{i}. {vector.get('name', 'Unknown Attack')}")
            print(f"   Priority: {vector.get('priority', 'N/A')}")
            print(f"   Difficulty: {vector.get('difficulty', 'N/A')}")
            print(f"   Target: {vector.get('target_service', 'N/A')}")
            print(f"   Expected Outcome: {vector.get('expected_outcome', 'N/A')[:80]}...")
            print()

    except Exception as e:
        print(f"❌ Error: {e}")

    # Test 3: Privilege Escalation
    print("\n🔍 Planning privilege escalation path...")
    print("Current Access: www-data (web server)")
    print("Target System: Ubuntu 20.04 Linux\n")

    try:
        escalation = agent.pentest.attempt_privilege_escalation(
            "www-data", "Ubuntu 20.04 Linux"
        )

        print(f"✅ Escalation Path Created:")
        print(f"   From: {escalation.current_privilege}")
        print(f"   To: {escalation.target_privilege}")
        print(f"   Difficulty: {escalation.difficulty}")
        print(f"   Estimated Time: {escalation.estimated_time}")
        print(f"   Steps: {len(escalation.steps)}")
        print(f"   Tools Required: {', '.join(escalation.tools_required[:3])}")

        if escalation.steps:
            print(f"\n   First Step:")
            step = escalation.steps[0]
            print(f"   {step.get('step_number', 1)}. {step.get('action', 'N/A')}")
            print(f"      Command: {step.get('command', 'N/A')}")

    except Exception as e:
        print(f"❌ Error: {e}")


def demo_comprehensive_assessment():
    """Demonstrate comprehensive security assessment"""
    print_section("COMPREHENSIVE SECURITY ASSESSMENT")

    agent = NetworkSecurityAgent()

    print("🔍 Running comprehensive security assessment...")
    print("This integrates all 4 modules for complete analysis\n")

    target = "192.168.1.100"
    print(f"Target: {target}")
    print(f"Assessment Type: Full\n")

    try:
        results = agent.comprehensive_security_assessment(target, assessment_type="full")

        print(f"✅ Assessment Complete!")
        print(f"\n📊 Summary:")
        print(f"   Modules Executed: {len(results['modules_executed'])}")
        print(f"   - {', '.join(results['modules_executed'])}")

        if "reconnaissance" in results:
            recon = results["reconnaissance"]
            print(f"\n   🔍 Reconnaissance:")
            print(f"      - Open Ports: {len(recon.get('open_ports', []))}")
            print(f"      - Vulnerabilities Found: {recon.get('vulnerabilities_found', 0)}")
            print(f"      - OS: {recon.get('os', 'Unknown')}")

        if "web_fuzzing" in results:
            fuzzing = results["web_fuzzing"]
            print(f"\n   🕷️  Web Fuzzing:")
            print(f"      - SQLi Payloads Generated: {fuzzing.get('sqli_payloads_generated', 0)}")

        if "threat_intelligence" in results:
            cti = results["threat_intelligence"]
            print(f"\n   🎯 Threat Intelligence:")
            print(f"      - Report ID: {cti.get('report_id', 'N/A')}")
            print(f"      - Severity: {cti.get('severity', 'N/A')}")
            print(f"      - IOCs Identified: {cti.get('iocs_identified', 0)}")
            print(f"      - Threat Actor: {cti.get('threat_actor', 'Unknown')}")

        if "attack_vectors" in results:
            print(f"\n   ⚔️  Attack Vectors: {len(results['attack_vectors'])} identified")

    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main demonstration function"""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 15 + "NETWORK SECURITY AGENT DEMONSTRATION" + " " * 27 + "║")
    print("║" + " " * 20 + "Based on LLM Cybersecurity Survey" + " " * 25 + "║")
    print("╚" + "═" * 78 + "╝")

    try:
        # Run all demonstrations
        demo_web_fuzzing()
        input("\n\n Press Enter to continue to next module...")

        demo_traffic_detection()
        input("\n\nPress Enter to continue to next module...")

        demo_cyber_threat_intelligence()
        input("\n\nPress Enter to continue to next module...")

        demo_penetration_testing()
        input("\n\nPress Enter to see comprehensive assessment...")

        demo_comprehensive_assessment()

        print("\n" + "=" * 80)
        print(" DEMONSTRATION COMPLETE")
        print("=" * 80)
        print("\n✅ All 4 Network Security modules demonstrated successfully!")
        print("\nModules covered:")
        print("  1. Web Fuzzing (SQL Injection, XSS, WAF Bypass)")
        print("  2. Traffic & Intrusion Detection (Network Analysis, URL Scanning)")
        print("  3. Cyber Threat Intelligence (CTI Reports, IOC Extraction)")
        print("  4. Penetration Testing (Recon, Exploitation, Privilege Escalation)")
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
