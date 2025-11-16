"""
System Log Analysis Module
Anomaly detection and root cause analysis in system logs using LLM
Based on LLM log analysis approaches from the research paper
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import pandas as pd

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LogAnomaly:
    """Detected log anomaly"""
    anomaly_id: str
    timestamp: str
    log_entry: str
    anomaly_type: str
    severity: str
    description: str
    root_cause: str
    recommendations: List[str]


@dataclass
class LogAnalysisReport:
    """Log analysis report"""
    report_id: str
    total_logs: int
    anomalies_found: int
    anomalies: List[LogAnomaly]
    summary: str
    trends: List[str]


class SystemLogAnalysisModule:
    """System Log Analysis Module using LLM"""

    def __init__(self):
        self.llm_client = LLMClient()
        logger.info("System Log Analysis Module initialized")

    def parse_logs(self, log_file_content: str) -> pd.DataFrame:
        """Parse log file into structured format"""
        logger.info("Parsing log file")

        # Simple parsing - in real implementation would use proper log parsers
        lines = log_file_content.strip().split('\n')
        return pd.DataFrame({"log_entry": lines})

    def detect_anomalies(self, logs: pd.DataFrame) -> LogAnalysisReport:
        """Detect anomalies in logs"""
        logger.info(f"Analyzing {len(logs)} log entries for anomalies")

        # Get sample logs for analysis
        sample_logs = logs.head(20)["log_entry"].tolist()
        logs_text = "\n".join(sample_logs)

        prompt = f"""Analyze these system logs for anomalies:

```
{logs_text}
```

Identify:
- Error patterns
- Unusual access attempts
- Performance issues
- Security incidents
- System failures

For each anomaly, provide JSON:
{{
    "anomalies": [
        {{
            "timestamp": "when it occurred",
            "log_entry": "the log line",
            "anomaly_type": "error|security|performance|other",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "description": "what's anomalous",
            "root_cause": "likely cause",
            "recommendations": ["how to fix"]
        }}
    ],
    "summary": "overall analysis",
    "trends": ["observed patterns"]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=2000)

            anomalies = []
            for i, anom_data in enumerate(result.get("anomalies", [])):
                anomaly = LogAnomaly(
                    anomaly_id=f"ANOM-{i+1:03d}",
                    timestamp=anom_data.get("timestamp", ""),
                    log_entry=anom_data.get("log_entry", ""),
                    anomaly_type=anom_data.get("anomaly_type", "other"),
                    severity=anom_data.get("severity", "MEDIUM"),
                    description=anom_data.get("description", ""),
                    root_cause=anom_data.get("root_cause", ""),
                    recommendations=anom_data.get("recommendations", [])
                )
                anomalies.append(anomaly)

            report = LogAnalysisReport(
                report_id=f"LOGRPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                total_logs=len(logs),
                anomalies_found=len(anomalies),
                anomalies=anomalies,
                summary=result.get("summary", ""),
                trends=result.get("trends", [])
            )

            logger.info(f"Analysis complete: {len(anomalies)} anomalies found")
            return report

        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            raise

    def identify_root_cause(self, error_logs: List[str]) -> Dict[str, Any]:
        """Identify root cause of errors"""
        logger.info(f"Analyzing root cause for {len(error_logs)} errors")

        logs_text = "\n".join(error_logs[:10])

        prompt = f"""Analyze these error logs to identify the root cause:

```
{logs_text}
```

Provide:
1. Root cause analysis
2. Timeline of events
3. Impact assessment
4. Remediation steps

JSON format:
{{
    "root_cause": "identified root cause",
    "timeline": ["sequence of events"],
    "impact": "what was affected",
    "remediation": ["steps to fix"],
    "prevention": ["how to prevent"]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1500)
            logger.info("Root cause analysis complete")
            return result

        except Exception as e:
            logger.error(f"Root cause analysis failed: {e}")
            return {}

    def correlate_events(self, logs: pd.DataFrame, timeframe: str = "1h") -> List[Dict[str, Any]]:
        """Correlate log events to identify patterns"""
        logger.info(f"Correlating events within {timeframe}")

        sample_logs = logs.head(15)["log_entry"].tolist()
        logs_text = "\n".join(sample_logs)

        prompt = f"""Correlate these log events to identify patterns:

Timeframe: {timeframe}

Logs:
```
{logs_text}
```

Identify:
- Related events
- Event sequences
- Causal relationships
- Patterns

Provide JSON with correlated event groups."""

        try:
            result = self.llm_client.complete_with_json(prompt)
            return result.get("correlations", [])
        except Exception as e:
            logger.error(f"Event correlation failed: {e}")
            return []


# Example usage
if __name__ == "__main__":
    analyzer = SystemLogAnalysisModule()

    sample_logs = """
2025-11-16 10:00:01 INFO: Application started successfully
2025-11-16 10:00:15 INFO: User admin logged in
2025-11-16 10:01:30 WARNING: High memory usage detected (85%)
2025-11-16 10:02:45 ERROR: Database connection timeout
2025-11-16 10:02:46 ERROR: Failed to execute query: Connection lost
2025-11-16 10:03:00 ERROR: Database connection timeout
2025-11-16 10:03:15 CRITICAL: Service crashed - OutOfMemoryError
2025-11-16 10:03:20 WARNING: Failed login attempt for user 'admin' from 192.168.1.100
2025-11-16 10:03:25 WARNING: Failed login attempt for user 'admin' from 192.168.1.100
2025-11-16 10:03:30 WARNING: Failed login attempt for user 'root' from 192.168.1.100
2025-11-16 10:04:00 INFO: Service restarted
"""

    print("=" * 70)
    print("SYSTEM LOG ANALYSIS DEMONSTRATION")
    print("=" * 70)

    try:
        # Parse logs
        logs_df = analyzer.parse_logs(sample_logs)
        print(f"\nTotal logs: {len(logs_df)}")

        # Detect anomalies
        report = analyzer.detect_anomalies(logs_df)

        print(f"\nAnomalies Found: {report.anomalies_found}")
        print(f"\nSummary: {report.summary}")

        print(f"\nDetailed Anomalies:")
        for anom in report.anomalies:
            print(f"\n  {anom.anomaly_id}: {anom.anomaly_type.upper()}")
            print(f"  Severity: {anom.severity}")
            print(f"  Description: {anom.description}")
            print(f"  Root Cause: {anom.root_cause}")
            if anom.recommendations:
                print(f"  Recommendation: {anom.recommendations[0]}")

        if report.trends:
            print(f"\nTrends Observed:")
            for trend in report.trends:
                print(f"  - {trend}")

    except Exception as e:
        print(f"Error: {e}")
