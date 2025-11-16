"""
Blockchain Security Agent
Coordinates all blockchain security modules
"""

from typing import Dict, Any, List, Optional

from .smart_contract_security import SmartContractSecurityModule
from .transaction_anomaly_detection import TransactionAnomalyDetectionModule

from src.utils.logger import get_logger
from src.utils.config_loader import get_config

logger = get_logger(__name__)


class BlockchainSecurityAgent:
    """
    Blockchain Security Agent
    Coordinates smart contract auditing and transaction anomaly detection
    """

    def __init__(self):
        """Initialize Blockchain Security Agent"""
        self.config = get_config()

        # Initialize modules
        self.smart_contract = SmartContractSecurityModule()
        self.transaction_monitor = TransactionAnomalyDetectionModule()

        logger.info("Blockchain Security Agent initialized with all modules")

    def comprehensive_contract_audit(self, contract_code: str, contract_name: str) -> Dict[str, Any]:
        """
        Perform comprehensive smart contract security audit

        Args:
            contract_code: Solidity contract code
            contract_name: Contract name

        Returns:
            Dict: Complete audit results
        """
        logger.info(f"Performing comprehensive audit of {contract_name}")

        results = {}

        try:
            # Full audit
            audit = self.smart_contract.audit_contract(contract_code, contract_name)
            results["audit"] = {
                "security_score": audit.security_score,
                "overall_risk": audit.overall_risk,
                "vulnerabilities_count": len(audit.vulnerabilities),
                "critical_count": sum(1 for v in audit.vulnerabilities if v.severity == "CRITICAL"),
                "high_count": sum(1 for v in audit.vulnerabilities if v.severity == "HIGH"),
            }

            # Reentrancy check
            reentrancy = self.smart_contract.detect_reentrancy(contract_code)
            results["reentrancy"] = {
                "vulnerable": reentrancy.get("vulnerable", False),
                "severity": reentrancy.get("severity", "NONE"),
            }

            # Access control analysis
            access_control = self.smart_contract.analyze_access_control(contract_code)
            results["access_control"] = {
                "implemented": access_control.get("access_control_implemented", False),
                "centralization_risk": access_control.get("centralization_risk", "UNKNOWN"),
                "vulnerabilities": len(access_control.get("vulnerabilities", [])),
            }

            # Security patterns
            patterns = self.smart_contract.check_security_patterns(contract_code)
            results["security_patterns"] = {
                "total_checked": len(patterns),
                "implemented": sum(1 for p in patterns if p.implemented),
            }

            # Overall recommendation
            if audit.overall_risk in ["CRITICAL", "HIGH"]:
                results["recommendation"] = "DO NOT DEPLOY - Critical vulnerabilities found"
            elif audit.security_score < 70:
                results["recommendation"] = "Requires remediation before deployment"
            else:
                results["recommendation"] = "Acceptable with minor improvements"

            return results

        except Exception as e:
            logger.error(f"Comprehensive contract audit failed: {e}")
            return {"error": str(e)}

    def monitor_transaction_activity(
        self, transactions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Monitor and analyze transaction activity for anomalies

        Args:
            transactions: List of transactions to monitor

        Returns:
            Dict: Monitoring results
        """
        logger.info(f"Monitoring {len(transactions)} transactions")

        results = {
            "total_analyzed": len(transactions),
            "anomalies_detected": 0,
            "high_risk_transactions": [],
            "suspicious_addresses": [],
        }

        try:
            for tx in transactions:
                # Analyze each transaction
                anomaly = self.transaction_monitor.analyze_transaction(tx)

                if anomaly.is_anomalous:
                    results["anomalies_detected"] += 1

                    if anomaly.severity in ["CRITICAL", "HIGH"]:
                        results["high_risk_transactions"].append({
                            "hash": anomaly.transaction_hash,
                            "type": anomaly.anomaly_type,
                            "severity": anomaly.severity,
                            "risk_score": anomaly.risk_score,
                        })

            logger.info(f"Detected {results['anomalies_detected']} anomalies")
            return results

        except Exception as e:
            logger.error(f"Transaction monitoring failed: {e}")
            return {"error": str(e)}

    def investigate_address(
        self, address: str, transaction_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Investigate blockchain address

        Args:
            address: Address to investigate
            transaction_history: Address transaction history

        Returns:
            Dict: Investigation results
        """
        logger.info(f"Investigating address: {address}")

        try:
            # Address analysis
            analysis = self.transaction_monitor.analyze_address(address, transaction_history)

            # Money laundering check
            if len(transaction_history) > 1:
                aml_alert = self.transaction_monitor.detect_money_laundering(transaction_history)
            else:
                aml_alert = None

            return {
                "address": address,
                "reputation_score": analysis.reputation_score,
                "is_suspicious": analysis.is_suspicious,
                "address_type": analysis.address_type,
                "risk_factors": analysis.risk_factors,
                "aml_alert": {
                    "detected": aml_alert.confidence > 0.5 if aml_alert else False,
                    "pattern": aml_alert.laundering_pattern if aml_alert else None,
                    "confidence": aml_alert.confidence if aml_alert else 0.0,
                } if aml_alert else None,
            }

        except Exception as e:
            logger.error(f"Address investigation failed: {e}")
            return {"error": str(e)}

    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get agent status and capabilities

        Returns:
            Dict: Agent status information
        """
        return {
            "agent_name": "Blockchain Security Agent",
            "status": "active",
            "modules": {
                "smart_contract_security": "active",
                "transaction_anomaly_detection": "active",
            },
            "capabilities": [
                "Smart contract security auditing (Solidity)",
                "Vulnerability detection (reentrancy, access control, etc.)",
                "Security pattern analysis",
                "Transaction anomaly detection",
                "Address reputation analysis",
                "Money laundering detection",
                "Flash loan attack detection",
                "DeFi exploit identification",
            ],
        }


# Example usage
if __name__ == "__main__":
    agent = BlockchainSecurityAgent()

    # Get agent status
    print("=" * 70)
    print("BLOCKCHAIN SECURITY AGENT STATUS")
    print("=" * 70)
    status = agent.get_agent_status()
    print(f"Agent: {status['agent_name']}")
    print(f"Status: {status['status']}")
    print("\nCapabilities:")
    for capability in status["capabilities"]:
        print(f"  - {capability}")

    # Test contract audit
    print("\n" + "=" * 70)
    print("COMPREHENSIVE CONTRACT AUDIT")
    print("=" * 70)

    contract_code = """
    pragma solidity ^0.8.0;
    contract SimpleBank {
        mapping(address => uint) balances;
        function withdraw(uint amount) public {
            (bool success,) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """

    audit_results = agent.comprehensive_contract_audit(contract_code, "SimpleBank")
    print(f"Security Score: {audit_results['audit']['security_score']:.1f}/100")
    print(f"Overall Risk: {audit_results['audit']['overall_risk']}")
    print(f"Vulnerabilities: {audit_results['audit']['vulnerabilities_count']}")
    print(f"Reentrancy Vulnerable: {audit_results['reentrancy']['vulnerable']}")
    print(f"Recommendation: {audit_results['recommendation']}")

    # Test transaction monitoring
    print("\n" + "=" * 70)
    print("TRANSACTION MONITORING")
    print("=" * 70)

    transactions = [
        {"hash": "0x111", "value": 1000, "to": "normal_address"},
        {"hash": "0x222", "value": 50000, "to": "mixer_service", "gas_price": 500},
        {"hash": "0x333", "value": 100, "to": "exchange"},
    ]

    monitoring_results = agent.monitor_transaction_activity(transactions)
    print(f"Total Analyzed: {monitoring_results['total_analyzed']}")
    print(f"Anomalies Detected: {monitoring_results['anomalies_detected']}")
    print(f"High Risk Transactions: {len(monitoring_results['high_risk_transactions'])}")

    # Test address investigation
    print("\n" + "=" * 70)
    print("ADDRESS INVESTIGATION")
    print("=" * 70)

    address = "0xSUSPICIOUS123"
    tx_history = [
        {"from": address, "to": "mixer", "value": 100},
        {"from": "mixer", "to": address, "value": 95},
    ]

    investigation = agent.investigate_address(address, tx_history)
    print(f"Address: {investigation['address']}")
    print(f"Reputation Score: {investigation['reputation_score']:.1f}/100")
    print(f"Is Suspicious: {investigation['is_suspicious']}")
    print(f"Address Type: {investigation['address_type']}")
