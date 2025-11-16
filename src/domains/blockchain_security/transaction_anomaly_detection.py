"""
Transaction Anomaly Detection Module
Detects suspicious blockchain transactions and patterns
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TransactionAnomaly:
    """Transaction anomaly detection result"""

    transaction_hash: str
    is_anomalous: bool
    anomaly_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    indicators: List[str]
    risk_score: float
    explanation: str
    recommended_action: str


@dataclass
class AddressAnalysis:
    """Blockchain address analysis"""

    address: str
    reputation_score: float
    is_suspicious: bool
    address_type: str  # exchange, contract, mixer, regular
    risk_factors: List[str]
    transaction_patterns: List[str]
    associated_threats: List[str]


@dataclass
class MoneyLaunderingAlert:
    """Money laundering detection alert"""

    alert_id: str
    timestamp: str
    confidence: float
    laundering_pattern: str
    involved_addresses: List[str]
    transaction_chain: List[str]
    total_amount: float
    description: str
    evidence: List[str]


class TransactionAnomalyDetectionModule:
    """
    Transaction Anomaly Detection Module
    Detects suspicious blockchain transactions and money laundering patterns
    """

    def __init__(self):
        """Initialize transaction anomaly detection module"""
        self.llm_client = LLMClient()
        logger.info("Transaction Anomaly Detection Module initialized")

    def analyze_transaction(
        self, transaction: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> TransactionAnomaly:
        """
        Analyze individual transaction for anomalies

        Args:
            transaction: Transaction data
            context: Additional context (historical data, network info)

        Returns:
            TransactionAnomaly: Anomaly analysis result
        """
        logger.info(f"Analyzing transaction: {transaction.get('hash', 'unknown')}")

        system_message = """You are a blockchain forensics expert specializing in transaction analysis.
Detect suspicious transactions including:
- Unusually large transfers
- Mixer/tumbler usage
- Rapid fund movement (layering)
- Dusting attacks
- Flash loan exploits
- Wash trading
- Front-running
- Sandwich attacks
- Rugpull indicators"""

        tx_str = "\n".join([f"{k}: {v}" for k, v in transaction.items()])
        context_str = ""
        if context:
            context_str = f"\n\nContext:\n{context}"

        prompt = f"""Analyze this blockchain transaction for anomalies:

Transaction:
{tx_str}
{context_str}

Provide analysis in JSON format:
{{
    "is_anomalous": boolean,
    "anomaly_type": "large_transfer" | "mixer_usage" | "flash_loan" | "front_running" | "rugpull" | "normal",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "confidence": float (0-1),
    "indicators": [list of suspicious indicators],
    "risk_score": float (0-100),
    "explanation": "detailed explanation",
    "recommended_action": "action to take"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return TransactionAnomaly(
                transaction_hash=transaction.get("hash", "unknown"),
                is_anomalous=result.get("is_anomalous", False),
                anomaly_type=result.get("anomaly_type", "normal"),
                severity=result.get("severity", "LOW"),
                confidence=result.get("confidence", 0.0),
                indicators=result.get("indicators", []),
                risk_score=result.get("risk_score", 0.0),
                explanation=result.get("explanation", ""),
                recommended_action=result.get("recommended_action", ""),
            )

        except Exception as e:
            logger.error(f"Transaction analysis failed: {e}")
            return TransactionAnomaly(
                transaction_hash=transaction.get("hash", "error"),
                is_anomalous=False,
                anomaly_type="error",
                severity="UNKNOWN",
                confidence=0.0,
                indicators=[],
                risk_score=0.0,
                explanation=f"Analysis error: {e}",
                recommended_action="Manual review required",
            )

    def analyze_address(
        self, address: str, transaction_history: List[Dict[str, Any]]
    ) -> AddressAnalysis:
        """
        Analyze blockchain address reputation and behavior

        Args:
            address: Blockchain address
            transaction_history: Address transaction history

        Returns:
            AddressAnalysis: Address analysis result
        """
        logger.info(f"Analyzing address: {address}")

        system_message = """You are a blockchain address intelligence expert.
Analyze addresses for:
- Exchange vs personal wallet vs contract
- Known threat actors
- Mixing/tumbling behavior
- Association with hacks or scams
- Transaction patterns
- Reputation score"""

        history_summary = self._summarize_transactions(transaction_history)

        prompt = f"""Analyze this blockchain address:

Address: {address}

Transaction History Summary:
{history_summary}

Provide analysis in JSON format:
{{
    "reputation_score": float (0-100, higher is better),
    "is_suspicious": boolean,
    "address_type": "exchange" | "contract" | "mixer" | "regular" | "unknown",
    "risk_factors": [list of risk factors],
    "transaction_patterns": [observed patterns],
    "associated_threats": [any known associations with threats]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return AddressAnalysis(
                address=address,
                reputation_score=result.get("reputation_score", 50.0),
                is_suspicious=result.get("is_suspicious", False),
                address_type=result.get("address_type", "unknown"),
                risk_factors=result.get("risk_factors", []),
                transaction_patterns=result.get("transaction_patterns", []),
                associated_threats=result.get("associated_threats", []),
            )

        except Exception as e:
            logger.error(f"Address analysis failed: {e}")
            return AddressAnalysis(
                address=address,
                reputation_score=50.0,
                is_suspicious=False,
                address_type="unknown",
                risk_factors=[],
                transaction_patterns=[],
                associated_threats=[],
            )

    def detect_money_laundering(
        self, transaction_chain: List[Dict[str, Any]]
    ) -> MoneyLaunderingAlert:
        """
        Detect money laundering patterns in transaction chains

        Args:
            transaction_chain: Chain of related transactions

        Returns:
            MoneyLaunderingAlert: Money laundering detection result
        """
        logger.info(f"Analyzing {len(transaction_chain)} transactions for laundering")

        system_message = """You are an anti-money laundering (AML) expert for blockchain.
Detect laundering patterns:
- Placement: Initial deposit of illicit funds
- Layering: Complex transactions to obscure origin
- Integration: Reintroduction to legitimate economy
- Structuring/smurfing
- Chain hopping
- Peel chains
- Mixer usage"""

        chain_summary = self._summarize_transactions(transaction_chain)

        prompt = f"""Analyze this transaction chain for money laundering:

Transaction Chain ({len(transaction_chain)} transactions):
{chain_summary}

Provide AML analysis in JSON format:
{{
    "confidence": float (0-1),
    "laundering_pattern": "layering" | "structuring" | "mixing" | "chain_hopping" | "peel_chain" | "none",
    "involved_addresses": [list of suspicious addresses],
    "transaction_chain": [list of transaction hashes in order],
    "total_amount": estimated total amount,
    "description": "detailed description of laundering scheme",
    "evidence": [list of evidence supporting the finding]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            alert_id = f"aml_{datetime.now().timestamp()}"

            return MoneyLaunderingAlert(
                alert_id=alert_id,
                timestamp=datetime.now().isoformat(),
                confidence=result.get("confidence", 0.0),
                laundering_pattern=result.get("laundering_pattern", "none"),
                involved_addresses=result.get("involved_addresses", []),
                transaction_chain=result.get("transaction_chain", []),
                total_amount=result.get("total_amount", 0.0),
                description=result.get("description", ""),
                evidence=result.get("evidence", []),
            )

        except Exception as e:
            logger.error(f"Money laundering detection failed: {e}")
            return MoneyLaunderingAlert(
                alert_id="error",
                timestamp=datetime.now().isoformat(),
                confidence=0.0,
                laundering_pattern="error",
                involved_addresses=[],
                transaction_chain=[],
                total_amount=0.0,
                description=f"Analysis error: {e}",
                evidence=[],
            )

    def detect_flash_loan_attack(
        self, transaction: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect flash loan attacks

        Args:
            transaction: Transaction to analyze

        Returns:
            Dict: Flash loan attack analysis
        """
        logger.info("Analyzing for flash loan attack")

        system_message = """You are a DeFi security expert specializing in flash loan attacks.
Identify flash loan attack patterns:
- Large uncollateralized loans
- Price oracle manipulation
- Arbitrage exploitation
- Governance attacks
- Re-entrancy combined with flash loans"""

        tx_str = "\n".join([f"{k}: {v}" for k, v in transaction.items()])

        prompt = f"""Analyze this transaction for flash loan attack:

Transaction:
{tx_str}

Provide analysis in JSON format:
{{
    "is_flash_loan_attack": boolean,
    "confidence": float (0-1),
    "attack_type": "oracle_manipulation" | "arbitrage" | "governance" | "reentrancy" | "none",
    "loan_amount": estimated loan amount or null,
    "profit_extracted": estimated profit or null,
    "affected_protocols": [list of affected DeFi protocols],
    "attack_steps": [description of attack steps],
    "impact": "description of impact"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "is_flash_loan_attack": result.get("is_flash_loan_attack", False),
                "confidence": result.get("confidence", 0.0),
                "attack_type": result.get("attack_type", "none"),
                "loan_amount": result.get("loan_amount"),
                "profit_extracted": result.get("profit_extracted"),
                "affected_protocols": result.get("affected_protocols", []),
                "attack_steps": result.get("attack_steps", []),
                "impact": result.get("impact", ""),
            }

        except Exception as e:
            logger.error(f"Flash loan attack detection failed: {e}")
            return {"error": str(e), "is_flash_loan_attack": False}

    def _summarize_transactions(self, transactions: List[Dict[str, Any]]) -> str:
        """Summarize transaction list for analysis"""
        if not transactions:
            return "No transactions"

        summary = [f"Total transactions: {len(transactions)}"]

        if transactions:
            # Calculate statistics
            total_value = sum(
                float(tx.get("value", 0)) for tx in transactions if "value" in tx
            )
            summary.append(f"Total value: {total_value}")

            # Sample transactions
            summary.append("\nSample transactions:")
            for tx in transactions[:3]:
                summary.append(str(tx))

        return "\n".join(summary)


# Example usage
if __name__ == "__main__":
    detector = TransactionAnomalyDetectionModule()

    # Test transaction anomaly detection
    print("=" * 70)
    print("TRANSACTION ANOMALY DETECTION")
    print("=" * 70)

    suspicious_tx = {
        "hash": "0xabc123...",
        "from": "0x1234...",
        "to": "0x5678...",
        "value": 10000,  # ETH
        "gas_price": 500,  # Gwei - unusually high
        "timestamp": "2025-01-15 02:30:00",
        "contract_calls": ["mixer_contract", "tumbler_service"],
    }

    anomaly = detector.analyze_transaction(suspicious_tx)
    print(f"Transaction: {anomaly.transaction_hash}")
    print(f"Is Anomalous: {anomaly.is_anomalous}")
    print(f"Anomaly Type: {anomaly.anomaly_type}")
    print(f"Severity: {anomaly.severity}")
    print(f"Risk Score: {anomaly.risk_score:.1f}/100")
    print(f"Confidence: {anomaly.confidence:.2f}")
    print(f"Indicators: {', '.join(anomaly.indicators[:3])}")

    # Test address analysis
    print("\n" + "=" * 70)
    print("ADDRESS REPUTATION ANALYSIS")
    print("=" * 70)

    address = "0xSUSPICIOUS..."
    tx_history = [
        {"type": "send", "value": 100, "to": "mixer"},
        {"type": "receive", "value": 95, "from": "mixer"},
        {"type": "send", "value": 90, "to": "exchange"},
    ]

    address_analysis = detector.analyze_address(address, tx_history)
    print(f"Address: {address_analysis.address}")
    print(f"Reputation Score: {address_analysis.reputation_score:.1f}/100")
    print(f"Is Suspicious: {address_analysis.is_suspicious}")
    print(f"Address Type: {address_analysis.address_type}")
    print(f"Risk Factors: {len(address_analysis.risk_factors)}")

    # Test money laundering detection
    print("\n" + "=" * 70)
    print("MONEY LAUNDERING DETECTION")
    print("=" * 70)

    transaction_chain = [
        {"hash": "0x111", "from": "A", "to": "B", "value": 1000},
        {"hash": "0x222", "from": "B", "to": "C", "value": 500},
        {"hash": "0x333", "from": "B", "to": "D", "value": 500},
        {"hash": "0x444", "from": "C", "to": "mixer", "value": 500},
        {"hash": "0x555", "from": "mixer", "to": "E", "value": 475},
    ]

    aml_alert = detector.detect_money_laundering(transaction_chain)
    print(f"Alert ID: {aml_alert.alert_id}")
    print(f"Confidence: {aml_alert.confidence:.2f}")
    print(f"Laundering Pattern: {aml_alert.laundering_pattern}")
    print(f"Involved Addresses: {len(aml_alert.involved_addresses)}")
    print(f"Total Amount: {aml_alert.total_amount}")

    # Test flash loan attack detection
    print("\n" + "=" * 70)
    print("FLASH LOAN ATTACK DETECTION")
    print("=" * 70)

    flash_loan_tx = {
        "hash": "0xflash123",
        "value": 0,
        "internal_transfers": [
            {"from": "lending_pool", "to": "attacker", "value": 1000000},
            {"from": "attacker", "to": "lending_pool", "value": 1000050},
        ],
        "contract_interactions": ["Aave", "Uniswap", "CompoundOracle"],
        "profit": 50000,
    }

    flash_result = detector.detect_flash_loan_attack(flash_loan_tx)
    print(f"Is Flash Loan Attack: {flash_result['is_flash_loan_attack']}")
    print(f"Confidence: {flash_result['confidence']:.2f}")
    print(f"Attack Type: {flash_result['attack_type']}")
    print(f"Profit Extracted: {flash_result.get('profit_extracted', 'N/A')}")
    print(f"Affected Protocols: {', '.join(flash_result['affected_protocols'])}")
