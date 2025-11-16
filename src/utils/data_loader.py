"""
Data Loader Module
Handles loading and processing security data
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import pandas as pd

from .logger import get_logger

logger = get_logger(__name__)


class DataLoader:
    """Load and process security datasets"""

    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize data loader

        Args:
            data_dir: Base directory for data (default: data/)
        """
        if data_dir is None:
            # Default to data directory in project root
            self.data_dir = Path(__file__).parent.parent.parent / "data"
        else:
            self.data_dir = Path(data_dir)

        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created data directory: {self.data_dir}")

    def load_json(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load JSON file

        Args:
            file_path: Path to JSON file

        Returns:
            Dict: Loaded JSON data
        """
        file_path = Path(file_path)

        if not file_path.is_absolute():
            file_path = self.data_dir / file_path

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Loaded JSON file: {file_path}")
            return data
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise

    def save_json(self, data: Dict[str, Any], file_path: Union[str, Path]) -> None:
        """
        Save data to JSON file

        Args:
            data: Data to save
            file_path: Output file path
        """
        file_path = Path(file_path)

        if not file_path.is_absolute():
            file_path = self.data_dir / file_path

        # Create parent directory if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved JSON file: {file_path}")

    def load_text(self, file_path: Union[str, Path]) -> str:
        """
        Load text file

        Args:
            file_path: Path to text file

        Returns:
            str: File contents
        """
        file_path = Path(file_path)

        if not file_path.is_absolute():
            file_path = self.data_dir / file_path

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            logger.info(f"Loaded text file: {file_path}")
            return content
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return ""

    def load_csv(self, file_path: Union[str, Path]) -> pd.DataFrame:
        """
        Load CSV file

        Args:
            file_path: Path to CSV file

        Returns:
            DataFrame: Loaded data
        """
        file_path = Path(file_path)

        if not file_path.is_absolute():
            file_path = self.data_dir / file_path

        try:
            df = pd.read_csv(file_path)
            logger.info(f"Loaded CSV file: {file_path} ({len(df)} rows)")
            return df
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return pd.DataFrame()

    def load_malware_samples(self) -> List[Dict[str, Any]]:
        """
        Load malware samples

        Returns:
            List[Dict]: Malware sample metadata
        """
        samples = []
        malware_dir = self.data_dir / "malware_samples"

        if not malware_dir.exists():
            logger.warning("Malware samples directory not found")
            return samples

        for file_path in malware_dir.glob("*.json"):
            sample = self.load_json(file_path)
            samples.append(sample)

        logger.info(f"Loaded {len(samples)} malware samples")
        return samples

    def load_phishing_emails(self) -> List[Dict[str, Any]]:
        """
        Load phishing email samples

        Returns:
            List[Dict]: Email samples
        """
        emails = []
        phishing_dir = self.data_dir / "phishing_emails"

        if not phishing_dir.exists():
            logger.warning("Phishing emails directory not found")
            return emails

        for file_path in phishing_dir.glob("*.json"):
            email = self.load_json(file_path)
            emails.append(email)

        logger.info(f"Loaded {len(emails)} phishing emails")
        return emails

    def load_smart_contracts(self) -> List[Dict[str, Any]]:
        """
        Load smart contract samples

        Returns:
            List[Dict]: Smart contract code and metadata
        """
        contracts = []
        contracts_dir = self.data_dir / "smart_contracts"

        if not contracts_dir.exists():
            logger.warning("Smart contracts directory not found")
            return contracts

        for file_path in contracts_dir.glob("*.sol"):
            contract = {
                "file": file_path.name,
                "code": self.load_text(file_path),
            }
            contracts.append(contract)

        logger.info(f"Loaded {len(contracts)} smart contracts")
        return contracts

    def load_network_logs(self) -> pd.DataFrame:
        """
        Load network traffic logs

        Returns:
            DataFrame: Network logs
        """
        logs_dir = self.data_dir / "network_logs"

        if not logs_dir.exists():
            logger.warning("Network logs directory not found")
            return pd.DataFrame()

        # Try to find CSV log files
        csv_files = list(logs_dir.glob("*.csv"))

        if not csv_files:
            logger.warning("No CSV log files found")
            return pd.DataFrame()

        # Load and combine all CSV files
        dfs = [self.load_csv(f) for f in csv_files]
        combined_df = pd.concat(dfs, ignore_index=True)

        logger.info(f"Loaded {len(combined_df)} network log entries")
        return combined_df

    def load_iot_traffic(self) -> pd.DataFrame:
        """
        Load IoT device traffic data

        Returns:
            DataFrame: IoT traffic logs
        """
        iot_dir = self.data_dir / "iot_traffic"

        if not iot_dir.exists():
            logger.warning("IoT traffic directory not found")
            return pd.DataFrame()

        csv_files = list(iot_dir.glob("*.csv"))

        if not csv_files:
            logger.warning("No IoT traffic files found")
            return pd.DataFrame()

        dfs = [self.load_csv(f) for f in csv_files]
        combined_df = pd.concat(dfs, ignore_index=True)

        logger.info(f"Loaded {len(combined_df)} IoT traffic entries")
        return combined_df

    def create_sample_data(self) -> None:
        """Create sample datasets for demonstration"""
        logger.info("Creating sample datasets...")

        # Sample phishing email
        phishing_email = {
            "id": "phish_001",
            "subject": "Urgent: Verify your account",
            "sender": "noreply@suspicious-bank.com",
            "body": "Your account will be suspended. Click here to verify: http://evil-site.com/verify",
            "is_phishing": True,
            "indicators": ["suspicious_url", "urgency", "account_threat"],
        }
        self.save_json(phishing_email, "phishing_emails/sample_001.json")

        # Sample vulnerable code
        vulnerable_code = {
            "id": "vuln_001",
            "language": "python",
            "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
            "vulnerabilities": ["SQL_INJECTION"],
            "severity": "HIGH",
        }
        self.save_json(vulnerable_code, "vulnerable_code/sample_001.json")

        # Sample smart contract
        smart_contract = """pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // Reentrancy vulnerability
    }
}"""
        (self.data_dir / "smart_contracts").mkdir(exist_ok=True)
        with open(
            self.data_dir / "smart_contracts" / "vulnerable_bank.sol", "w"
        ) as f:
            f.write(smart_contract)

        # Sample network log
        network_log = pd.DataFrame(
            {
                "timestamp": ["2025-01-01 10:00:00", "2025-01-01 10:01:00"],
                "src_ip": ["192.168.1.100", "10.0.0.50"],
                "dst_ip": ["8.8.8.8", "192.168.1.1"],
                "protocol": ["TCP", "UDP"],
                "port": [443, 53],
                "bytes": [1500, 512],
                "is_malicious": [False, True],
            }
        )
        (self.data_dir / "network_logs").mkdir(exist_ok=True)
        network_log.to_csv(
            self.data_dir / "network_logs" / "sample_traffic.csv", index=False
        )

        logger.info("Sample datasets created successfully")


# Example usage
if __name__ == "__main__":
    # Test data loader
    loader = DataLoader()

    # Create sample data
    loader.create_sample_data()

    # Load sample data
    phishing_emails = loader.load_phishing_emails()
    print(f"Loaded {len(phishing_emails)} phishing emails")

    smart_contracts = loader.load_smart_contracts()
    print(f"Loaded {len(smart_contracts)} smart contracts")

    network_logs = loader.load_network_logs()
    print(f"Loaded {len(network_logs)} network log entries")
