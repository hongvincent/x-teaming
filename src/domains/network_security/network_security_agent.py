"""
Network Security Agent
Coordinates all network security modules
"""

from typing import Dict, Any, List, Optional

from .web_fuzzing import WebFuzzingModule
from .traffic_detection import TrafficDetectionModule
from .cti import CTIModule
from .penetration_testing import PenetrationTestingModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class NetworkSecurityAgent:
    """
    Network Security Agent
    Coordinates web fuzzing, traffic detection, CTI, and penetration testing
    """

    def __init__(self):
        """Initialize Network Security Agent"""
        self.config = get_config()

        # Initialize modules
        self.web_fuzzing = WebFuzzingModule()
        self.traffic_detection = TrafficDetectionModule()
        self.cti = CTIModule()
        self.pentest = PenetrationTestingModule()

        logger.info("Network Security Agent initialized with all modules")

    def comprehensive_security_assessment(
        self, target: str, assessment_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security assessment

        Args:
            target: Target system (URL, IP, domain)
            assessment_type: Type of assessment (web, network, full)

        Returns:
            Dict: Complete assessment results
        """
        logger.info(
            f"Starting comprehensive security assessment of {target} (type: {assessment_type})"
        )

        results = {
            "target": target,
            "assessment_type": assessment_type,
            "modules_executed": [],
        }

        try:
            # 1. Reconnaissance
            if assessment_type in ["network", "full"]:
                logger.info("Phase 1: Reconnaissance")
                recon_data = self.pentest.perform_reconnaissance(target)
                results["reconnaissance"] = {
                    "open_ports": recon_data.open_ports,
                    "services": recon_data.services,
                    "os": recon_data.os_detection,
                    "vulnerabilities_found": len(recon_data.vulnerabilities),
                    "technologies": recon_data.technologies,
                }
                results["modules_executed"].append("reconnaissance")

                # 2. Attack vector analysis
                logger.info("Phase 2: Attack Vector Analysis")
                attack_vectors = self.pentest.suggest_attack_vectors(recon_data)
                results["attack_vectors"] = attack_vectors
                results["modules_executed"].append("attack_vector_analysis")

            # 3. Web fuzzing
            if assessment_type in ["web", "full"]:
                logger.info("Phase 3: Web Fuzzing")
                sqli_payloads = self.web_fuzzing.generate_sqli_payloads(target)
                results["web_fuzzing"] = {
                    "sqli_payloads_generated": len(sqli_payloads),
                    "sample_payloads": [
                        {
                            "payload": p.payload,
                            "severity": p.severity,
                            "description": p.description,
                        }
                        for p in sqli_payloads[:3]
                    ],
                }
                results["modules_executed"].append("web_fuzzing")

            # 4. Generate threat intelligence
            logger.info("Phase 4: Threat Intelligence Generation")
            incident_data = {
                "target": target,
                "assessment_date": "2025-01-01",
                "findings": str(results),
            }
            cti_report = self.cti.generate_threat_report(incident_data)
            results["threat_intelligence"] = {
                "report_id": cti_report.report_id,
                "severity": cti_report.severity,
                "iocs_identified": len(cti_report.iocs),
                "threat_actor": cti_report.threat_actor,
                "recommendations_count": len(cti_report.recommendations),
            }
            results["modules_executed"].append("threat_intelligence")

            logger.info(
                f"Comprehensive assessment complete. Executed {len(results['modules_executed'])} modules."
            )
            return results

        except Exception as e:
            logger.error(f"Comprehensive assessment failed: {e}")
            results["error"] = str(e)
            return results

    def monitor_network_traffic(
        self, traffic_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Monitor and analyze network traffic

        Args:
            traffic_data: Network traffic data

        Returns:
            Dict: Traffic analysis results
        """
        logger.info("Monitoring network traffic")

        # Analyze traffic for anomalies
        anomaly_report = self.traffic_detection.analyze_network_flow(traffic_data)

        # Extract URLs if present
        urls = traffic_data.get("urls", [])
        url_analysis = []
        if urls:
            url_analysis = self.traffic_detection.detect_malicious_urls(urls)

        return {
            "anomaly_detected": anomaly_report.anomaly_detected,
            "anomaly_type": anomaly_report.anomaly_type,
            "severity": anomaly_report.severity,
            "confidence": anomaly_report.confidence,
            "affected_ips": anomaly_report.affected_ips,
            "malicious_urls_detected": sum(1 for u in url_analysis if u.is_malicious),
            "recommendations": anomaly_report.recommendations,
        }

    def respond_to_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coordinate incident response

        Args:
            incident_data: Incident details

        Returns:
            Dict: Incident response plan
        """
        logger.info("Coordinating incident response")

        # Generate CTI report
        cti_report = self.cti.generate_threat_report(incident_data)

        # Extract IOCs
        incident_text = str(incident_data)
        iocs = self.cti.extract_iocs(incident_text)

        # Correlate threats
        correlation = {}
        if iocs:
            correlation = self.cti.correlate_threats(iocs)

        return {
            "cti_report_id": cti_report.report_id,
            "severity": cti_report.severity,
            "threat_actor": cti_report.threat_actor,
            "iocs_extracted": len(iocs),
            "campaign_identified": correlation.get("campaign_identified", False),
            "recommendations": cti_report.recommendations,
            "executive_summary": cti_report.executive_summary,
        }

    def test_web_security(
        self, target_url: str, form_data: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test web application security

        Args:
            target_url: Target web application URL
            form_data: Form data to test

        Returns:
            Dict: Web security test results
        """
        logger.info(f"Testing web security for {target_url}")

        results = {"target": target_url, "vulnerabilities": []}

        # SQL Injection testing
        sqli_payloads = self.web_fuzzing.generate_sqli_payloads(target_url, count=5)
        results["sqli_test"] = {
            "payloads_generated": len(sqli_payloads),
            "high_severity_count": sum(
                1 for p in sqli_payloads if p.severity == "HIGH" or p.severity == "CRITICAL"
            ),
        }

        # XSS testing
        if form_data:
            xss_report = self.web_fuzzing.detect_xss_vulnerabilities(form_data)
            results["xss_test"] = {
                "vulnerable": xss_report.vulnerable,
                "type": xss_report.vulnerability_type,
                "risk_level": xss_report.risk_level,
            }

            if xss_report.vulnerable:
                results["vulnerabilities"].append("XSS")

        # WAF bypass testing
        waf_bypass = self.web_fuzzing.test_waf_bypass("Generic WAF", "sqli")
        results["waf_bypass_test"] = {
            "payloads_generated": waf_bypass.get("total_generated", 0)
        }

        results["total_vulnerabilities_found"] = len(results["vulnerabilities"])

        return results

    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get agent status and capabilities

        Returns:
            Dict: Agent status information
        """
        return {
            "agent_name": "Network Security Agent",
            "status": "active",
            "modules": {
                "web_fuzzing": "active",
                "traffic_detection": "active",
                "cti": "active",
                "penetration_testing": "active",
            },
            "capabilities": [
                "Web vulnerability fuzzing (SQLi, XSS, RCE)",
                "Network traffic analysis and intrusion detection",
                "Cyber threat intelligence generation and IOC extraction",
                "Automated penetration testing",
                "Attack vector analysis",
                "Incident response coordination",
            ],
        }


# Example usage
if __name__ == "__main__":
    agent = NetworkSecurityAgent()

    # Get agent status
    print("=" * 70)
    print("NETWORK SECURITY AGENT STATUS")
    print("=" * 70)
    status = agent.get_agent_status()
    print(f"Agent: {status['agent_name']}")
    print(f"Status: {status['status']}")
    print("\nModules:")
    for module, state in status['modules'].items():
        print(f"  - {module}: {state}")
    print("\nCapabilities:")
    for capability in status['capabilities']:
        print(f"  - {capability}")

    # Test web security
    print("\n" + "=" * 70)
    print("WEB SECURITY ASSESSMENT")
    print("=" * 70)
    web_results = agent.test_web_security(
        "http://example.com/login",
        form_data={"username": "admin", "password": "password123"},
    )
    print(f"Target: {web_results['target']}")
    print(f"SQLi Payloads Generated: {web_results['sqli_test']['payloads_generated']}")
    print(f"XSS Vulnerable: {web_results.get('xss_test', {}).get('vulnerable', 'N/A')}")
    print(f"Total Vulnerabilities: {web_results['total_vulnerabilities_found']}")

    # Test network monitoring
    print("\n" + "=" * 70)
    print("NETWORK TRAFFIC MONITORING")
    print("=" * 70)
    traffic_data = {
        "src_ip": "10.0.0.50",
        "dst_ip": "8.8.8.8",
        "protocol": "TCP",
        "dst_port": 443,
        "bytes": 50000,
        "urls": ["http://google.com", "http://suspicious-domain.ru"],
    }
    traffic_results = agent.monitor_network_traffic(traffic_data)
    print(f"Anomaly Detected: {traffic_results['anomaly_detected']}")
    print(f"Anomaly Type: {traffic_results['anomaly_type']}")
    print(f"Severity: {traffic_results['severity']}")
    print(f"Malicious URLs: {traffic_results['malicious_urls_detected']}")

    # Test incident response
    print("\n" + "=" * 70)
    print("INCIDENT RESPONSE")
    print("=" * 70)
    incident = {
        "type": "data_breach",
        "source_ip": "203.0.113.50",
        "target": "database-server-01",
        "data_accessed": "customer_records",
    }
    incident_results = agent.respond_to_incident(incident)
    print(f"CTI Report: {incident_results['cti_report_id']}")
    print(f"Severity: {incident_results['severity']}")
    print(f"Threat Actor: {incident_results['threat_actor']}")
    print(f"IOCs Extracted: {incident_results['iocs_extracted']}")
    print(f"Campaign Identified: {incident_results['campaign_identified']}")
