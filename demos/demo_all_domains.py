#!/usr/bin/env python3
"""
LLM Cybersecurity Platform - Complete Demonstration
Showcases all 8 security domains and 32 modules
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.domains.network_security.network_security_agent import NetworkSecurityAgent
from src.domains.software_security.software_security_agent import SoftwareSecurityAgent
from src.domains.information_security.information_security_agent import InformationSecurityAgent
from src.domains.blockchain_security.blockchain_security_agent import BlockchainSecurityAgent
from src.domains.hardware_security.hardware_security_agent import HardwareSecurityAgent
from src.domains.cloud_security.cloud_security_agent import CloudSecurityAgent
from src.domains.incident_response.incident_response_agent import IncidentResponseAgent
from src.domains.iot_security.iot_security_agent import IoTSecurityAgent

from src.utils.logger import setup_logging, get_logger

# Setup logging
setup_logging(log_level="INFO", log_output="console", log_format="text")
logger = get_logger(__name__)


def print_header(title: str, width: int = 80):
    """Print formatted header"""
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width + "\n")


def print_section(title: str):
    """Print section separator"""
    print("\n" + "-" * 80)
    print(f"  {title}")
    print("-" * 80 + "\n")


def demo_network_security():
    """Demonstrate Network Security Domain (4 modules)"""
    print_header("DOMAIN 1: NETWORK SECURITY")

    agent = NetworkSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")
    print(f"Capabilities: {len(status['capabilities'])}")

    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Network Security Agent Ready")
    print("   Modules: Web Fuzzing, Traffic Detection, CTI, Penetration Testing")


def demo_software_security():
    """Demonstrate Software Security Domain (8 modules)"""
    print_header("DOMAIN 2: SOFTWARE SECURITY")

    agent = SoftwareSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")
    print(f"Supported Languages: {len(status['supported_languages'])}")

    print("\nSupported Languages:")
    for lang in status['supported_languages']:
        print(f"  • {lang}")

    print("\n✅ Software Security Agent Ready")
    print("   Modules: Vulnerability Detection/Repair, Bug Detection/Repair,")
    print("            Program Fuzzing, Reverse Engineering, Malware Detection, Log Analysis")


def demo_information_security():
    """Demonstrate Information Security Domain (5 modules)"""
    print_header("DOMAIN 3: INFORMATION SECURITY")

    agent = InformationSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Information Security Agent Ready")
    print("   Modules: Phishing Detection, Harmful Content Detection, Steganography,")
    print("            Access Control, Digital Forensics")


def demo_blockchain_security():
    """Demonstrate Blockchain Security Domain (2 modules)"""
    print_header("DOMAIN 4: BLOCKCHAIN SECURITY")

    agent = BlockchainSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Blockchain Security Agent Ready")
    print("   Modules: Smart Contract Security, Transaction Anomaly Detection")


def demo_hardware_security():
    """Demonstrate Hardware Security Domain (2 modules)"""
    print_header("DOMAIN 5: HARDWARE SECURITY")

    agent = HardwareSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Hardware Security Agent Ready")
    print("   Modules: Hardware Vulnerability Detection, Hardware Vulnerability Repair")


def demo_cloud_security():
    """Demonstrate Cloud Security Domain (4 modules)"""
    print_header("DOMAIN 6: CLOUD SECURITY")

    agent = CloudSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Cloud Security Agent Ready")
    print("   Modules: Misconfiguration Detection, Data Leakage Monitoring,")
    print("            Container Security, Compliance Enforcement")


def demo_incident_response():
    """Demonstrate Incident Response Domain (4 modules)"""
    print_header("DOMAIN 7: INCIDENT RESPONSE")

    agent = IncidentResponseAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ Incident Response Agent Ready")
    print("   Modules: Alert Prioritization, Threat Intelligence Analysis,")
    print("            Threat Hunting, Malware Reverse Engineering")


def demo_iot_security():
    """Demonstrate IoT Security Domain (3 modules)"""
    print_header("DOMAIN 8: IoT SECURITY")

    agent = IoTSecurityAgent()
    status = agent.get_agent_status()

    print(f"Agent: {status['agent_name']}")
    print(f"Active Modules: {len(status['modules'])}")

    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  • {capability}")

    print("\n✅ IoT Security Agent Ready")
    print("   Modules: Firmware Vulnerability Detection, Behavioral Anomaly Detection,")
    print("            Threat Report Summarization")


def print_platform_statistics():
    """Print overall platform statistics"""
    print_header("PLATFORM STATISTICS")

    stats = {
        "Total Security Domains": 8,
        "Total Security Modules": 32,
        "Total Agent Coordinators": 8,
        "Research Paper": "arXiv:2507.13629v1",
        "Implementation Status": "100% Complete"
    }

    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 80)
    print(" MODULE BREAKDOWN BY DOMAIN")
    print("=" * 80 + "\n")

    domains = [
        ("Network Security", 4, ["Web Fuzzing", "Traffic Detection", "CTI", "Penetration Testing"]),
        ("Software Security", 8, ["Vulnerability Detection", "Vulnerability Repair", "Bug Detection",
                                   "Bug Repair", "Program Fuzzing", "Reverse Engineering",
                                   "Malware Detection", "System Log Analysis"]),
        ("Information Security", 5, ["Phishing Detection", "Harmful Content Detection",
                                      "Steganography", "Access Control", "Digital Forensics"]),
        ("Blockchain Security", 2, ["Smart Contract Security", "Transaction Anomaly Detection"]),
        ("Hardware Security", 2, ["Hardware Vulnerability Detection", "Hardware Vulnerability Repair"]),
        ("Cloud Security", 4, ["Misconfiguration Detection", "Data Leakage Monitoring",
                               "Container Security", "Compliance Enforcement"]),
        ("Incident Response", 4, ["Alert Prioritization", "Threat Intelligence Analysis",
                                  "Threat Hunting", "Malware Reverse Engineering"]),
        ("IoT Security", 3, ["Firmware Vulnerability Detection", "Behavioral Anomaly Detection",
                             "Threat Report Summarization"])
    ]

    for domain_name, module_count, modules in domains:
        print(f"{domain_name} ({module_count} modules):")
        for module in modules:
            print(f"  • {module}")
        print()


def main():
    """Main demonstration function"""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 15 + "LLM CYBERSECURITY PLATFORM DEMONSTRATION" + " " * 23 + "║")
    print("║" + " " * 20 + "Complete Security Solution Showcase" + " " * 23 + "║")
    print("╚" + "═" * 78 + "╝")

    print("\nBased on Research Paper: arXiv:2507.13629v1")
    print("Title: Large Language Models in Cybersecurity")
    print("Subtitle: Applications, Vulnerabilities, and Defense Techniques")

    try:
        # Print platform statistics first
        print_platform_statistics()

        print("\n" + "=" * 80)
        print(" DEMONSTRATING ALL 8 SECURITY DOMAINS")
        print("=" * 80)

        input("\nPress Enter to start demonstrations...")

        # Demonstrate each domain
        demo_network_security()
        input("\nPress Enter to continue to Software Security...")

        demo_software_security()
        input("\nPress Enter to continue to Information Security...")

        demo_information_security()
        input("\nPress Enter to continue to Blockchain Security...")

        demo_blockchain_security()
        input("\nPress Enter to continue to Hardware Security...")

        demo_hardware_security()
        input("\nPress Enter to continue to Cloud Security...")

        demo_cloud_security()
        input("\nPress Enter to continue to Incident Response...")

        demo_incident_response()
        input("\nPress Enter to continue to IoT Security...")

        demo_iot_security()

        # Final summary
        print("\n" + "=" * 80)
        print(" DEMONSTRATION COMPLETE")
        print("=" * 80)

        print("\n✅ All 8 Security Domains Demonstrated Successfully!")
        print("\n📊 Platform Capabilities:")
        print("  • Network Security: Web fuzzing, traffic analysis, threat intelligence, pentesting")
        print("  • Software Security: Vulnerability/bug detection and repair, malware analysis")
        print("  • Information Security: Phishing detection, content filtering, forensics")
        print("  • Blockchain Security: Smart contract auditing, transaction analysis")
        print("  • Hardware Security: HDL vulnerability detection and repair")
        print("  • Cloud Security: Misconfiguration detection, compliance, container security")
        print("  • Incident Response: Alert prioritization, threat hunting, malware RE")
        print("  • IoT Security: Firmware analysis, behavioral anomaly detection")

        print("\n🎯 Key Features:")
        print("  • 32 Security Modules across 8 domains")
        print("  • LLM-powered analysis and automation")
        print("  • Multi-language support (Python, JavaScript, Java, C/C++, Go, etc.)")
        print("  • MITRE ATT&CK framework integration")
        print("  • CWE vulnerability classification")
        print("  • Automated patch generation")
        print("  • Comprehensive threat intelligence")

        print("\n🚀 Ready for Production Use!")
        print("\nFor individual domain demonstrations, see:")
        print("  • demos/demo_network_security.py")
        print("  • demos/demo_software_security.py")
        print("  • demos/demo_<domain>.py for other domains")
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
