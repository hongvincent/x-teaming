"""
Digital Forensics Module
Evidence extraction, timeline reconstruction, and forensic analysis
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ForensicEvidence:
    """Digital forensic evidence"""

    evidence_id: str
    evidence_type: str
    source: str
    timestamp: str
    hash_value: str
    relevance_score: float
    description: str
    chain_of_custody: List[str]


@dataclass
class TimelineEvent:
    """Timeline event for incident reconstruction"""

    event_id: str
    timestamp: str
    event_type: str
    source: str
    description: str
    artifacts: List[str]
    significance: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class ForensicAnalysis:
    """Complete forensic analysis result"""

    analysis_id: str
    incident_type: str
    timeline: List[TimelineEvent]
    key_findings: List[str]
    evidence_collected: List[ForensicEvidence]
    attack_vector: Optional[str]
    indicators_of_compromise: List[str]
    recommendations: List[str]
    report_timestamp: str


@dataclass
class MemoryAnalysis:
    """Memory forensics analysis"""

    process_analysis: List[Dict[str, Any]]
    network_connections: List[Dict[str, Any]]
    suspicious_artifacts: List[str]
    malware_detected: bool
    persistence_mechanisms: List[str]


class DigitalForensicsModule:
    """
    Digital Forensics Module
    Evidence extraction, timeline reconstruction, and forensic analysis
    """

    def __init__(self):
        """Initialize digital forensics module"""
        self.llm_client = LLMClient()
        logger.info("Digital Forensics Module initialized")

    def analyze_disk_image(
        self, disk_metadata: Dict[str, Any], file_list: List[Dict[str, Any]]
    ) -> ForensicAnalysis:
        """
        Analyze disk image for forensic evidence

        Args:
            disk_metadata: Disk image metadata
            file_list: List of files with metadata

        Returns:
            ForensicAnalysis: Comprehensive forensic analysis
        """
        logger.info("Analyzing disk image for forensic evidence")

        system_message = """You are a digital forensics expert.
Analyze disk images for evidence of security incidents:
- Deleted files and file recovery
- File system timeline analysis
- Hidden or suspicious files
- System artifacts (logs, registry, etc.)
- User activity patterns
- Evidence of data exfiltration"""

        metadata_str = "\n".join([f"{k}: {v}" for k, v in disk_metadata.items()])
        files_summary = self._summarize_file_list(file_list)

        prompt = f"""Analyze this disk image for forensic evidence:

Disk Metadata:
{metadata_str}

File Summary:
{files_summary}

Provide comprehensive forensic analysis in JSON format:
{{
    "incident_type": "data_breach" | "malware_infection" | "insider_threat" | "unauthorized_access" | "unknown",
    "key_findings": [list of critical findings],
    "attack_vector": "description of how attack occurred or null",
    "indicators_of_compromise": [list of IOCs found],
    "timeline_events": [
        {{
            "timestamp": "ISO 8601 timestamp",
            "event_type": "file_access" | "file_deletion" | "process_execution" | "network_activity",
            "source": "source of evidence",
            "description": "event description",
            "artifacts": [list of related artifacts],
            "significance": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        }}
    ],
    "evidence_items": [
        {{
            "evidence_type": "file" | "log" | "registry" | "network" | "memory",
            "source": "location of evidence",
            "hash_value": "SHA256 hash",
            "relevance_score": float (0-1),
            "description": "evidence description"
        }}
    ],
    "recommendations": [list of recommended actions]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            analysis_id = f"forensic_{datetime.now().timestamp()}"

            # Build timeline
            timeline = []
            for event in result.get("timeline_events", []):
                timeline.append(
                    TimelineEvent(
                        event_id=f"event_{len(timeline)}",
                        timestamp=event.get("timestamp", ""),
                        event_type=event.get("event_type", ""),
                        source=event.get("source", ""),
                        description=event.get("description", ""),
                        artifacts=event.get("artifacts", []),
                        significance=event.get("significance", "LOW"),
                    )
                )

            # Build evidence list
            evidence = []
            for item in result.get("evidence_items", []):
                evidence.append(
                    ForensicEvidence(
                        evidence_id=f"evidence_{len(evidence)}",
                        evidence_type=item.get("evidence_type", ""),
                        source=item.get("source", ""),
                        timestamp=datetime.now().isoformat(),
                        hash_value=item.get("hash_value", ""),
                        relevance_score=item.get("relevance_score", 0.0),
                        description=item.get("description", ""),
                        chain_of_custody=[f"Collected by system at {datetime.now().isoformat()}"],
                    )
                )

            return ForensicAnalysis(
                analysis_id=analysis_id,
                incident_type=result.get("incident_type", "unknown"),
                timeline=timeline,
                key_findings=result.get("key_findings", []),
                evidence_collected=evidence,
                attack_vector=result.get("attack_vector"),
                indicators_of_compromise=result.get("indicators_of_compromise", []),
                recommendations=result.get("recommendations", []),
                report_timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Disk image analysis failed: {e}")
            return ForensicAnalysis(
                analysis_id="error",
                incident_type="unknown",
                timeline=[],
                key_findings=[],
                evidence_collected=[],
                attack_vector=None,
                indicators_of_compromise=[],
                recommendations=[f"Analysis error: {e}"],
                report_timestamp=datetime.now().isoformat(),
            )

    def analyze_memory_dump(
        self, memory_data: Dict[str, Any]
    ) -> MemoryAnalysis:
        """
        Analyze memory dump for malware and suspicious activity

        Args:
            memory_data: Memory dump data and analysis

        Returns:
            MemoryAnalysis: Memory forensics results
        """
        logger.info("Analyzing memory dump")

        system_message = """You are a memory forensics expert.
Analyze memory dumps for:
- Running processes and DLLs
- Network connections
- Injected code
- Rootkits and hidden processes
- Malware artifacts
- Persistence mechanisms"""

        memory_str = "\n".join([f"{k}: {v}" for k, v in memory_data.items()])

        prompt = f"""Analyze this memory dump for suspicious activity:

Memory Data:
{memory_str}

Provide memory forensics analysis in JSON format:
{{
    "process_analysis": [
        {{
            "pid": "process ID",
            "name": "process name",
            "suspicious": boolean,
            "reason": "why suspicious or empty"
        }}
    ],
    "network_connections": [
        {{
            "remote_ip": "IP address",
            "port": port number,
            "process": "process name",
            "suspicious": boolean
        }}
    ],
    "suspicious_artifacts": [list of suspicious artifacts found],
    "malware_detected": boolean,
    "persistence_mechanisms": [list of persistence mechanisms found]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            return MemoryAnalysis(
                process_analysis=result.get("process_analysis", []),
                network_connections=result.get("network_connections", []),
                suspicious_artifacts=result.get("suspicious_artifacts", []),
                malware_detected=result.get("malware_detected", False),
                persistence_mechanisms=result.get("persistence_mechanisms", []),
            )

        except Exception as e:
            logger.error(f"Memory analysis failed: {e}")
            return MemoryAnalysis(
                process_analysis=[],
                network_connections=[],
                suspicious_artifacts=[],
                malware_detected=False,
                persistence_mechanisms=[],
            )

    def reconstruct_timeline(
        self, log_data: List[Dict[str, Any]], incident_window: Dict[str, str]
    ) -> List[TimelineEvent]:
        """
        Reconstruct incident timeline from logs

        Args:
            log_data: Log entries
            incident_window: Time window for incident

        Returns:
            List[TimelineEvent]: Reconstructed timeline
        """
        logger.info("Reconstructing incident timeline")

        system_message = """You are a forensic timeline analysis expert.
Reconstruct incident timelines by correlating log entries and identifying key events.
Focus on:
- Initial compromise
- Lateral movement
- Privilege escalation
- Data access
- Exfiltration
- Cleanup activities"""

        logs_summary = self._summarize_logs(log_data)
        window_str = f"Start: {incident_window.get('start', 'unknown')}, End: {incident_window.get('end', 'unknown')}"

        prompt = f"""Reconstruct the incident timeline from these logs:

Incident Window: {window_str}

Log Summary:
{logs_summary}

Create a chronological timeline in JSON format:
{{
    "timeline": [
        {{
            "timestamp": "ISO 8601 timestamp",
            "event_type": "event type",
            "source": "log source",
            "description": "what happened",
            "artifacts": [related log entries or evidence],
            "significance": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            timeline = []
            for event in result.get("timeline", []):
                timeline.append(
                    TimelineEvent(
                        event_id=f"event_{len(timeline)}",
                        timestamp=event.get("timestamp", ""),
                        event_type=event.get("event_type", ""),
                        source=event.get("source", ""),
                        description=event.get("description", ""),
                        artifacts=event.get("artifacts", []),
                        significance=event.get("significance", "LOW"),
                    )
                )

            logger.info(f"Reconstructed timeline with {len(timeline)} events")
            return timeline

        except Exception as e:
            logger.error(f"Timeline reconstruction failed: {e}")
            return []

    def extract_artifacts(
        self, evidence_source: str, artifact_types: List[str]
    ) -> List[ForensicEvidence]:
        """
        Extract specific artifacts from evidence

        Args:
            evidence_source: Source of evidence
            artifact_types: Types of artifacts to extract

        Returns:
            List[ForensicEvidence]: Extracted artifacts
        """
        logger.info(f"Extracting artifacts from {evidence_source}")

        system_message = """You are a digital forensics artifact extraction expert.
Extract and identify key artifacts including:
- Browser history and downloads
- Email communications
- File metadata
- System logs
- Registry keys
- Network artifacts"""

        artifacts_str = ", ".join(artifact_types)

        prompt = f"""Extract these artifacts from the evidence source:

Source: {evidence_source}
Artifact Types: {artifacts_str}

Identify and describe artifacts in JSON format:
{{
    "artifacts": [
        {{
            "evidence_type": "artifact type",
            "source": "specific location",
            "hash_value": "SHA256 hash if applicable",
            "relevance_score": float (0-1),
            "description": "artifact description"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            artifacts = []
            for item in result.get("artifacts", []):
                artifacts.append(
                    ForensicEvidence(
                        evidence_id=f"artifact_{len(artifacts)}",
                        evidence_type=item.get("evidence_type", ""),
                        source=item.get("source", ""),
                        timestamp=datetime.now().isoformat(),
                        hash_value=item.get("hash_value", ""),
                        relevance_score=item.get("relevance_score", 0.0),
                        description=item.get("description", ""),
                        chain_of_custody=[f"Extracted at {datetime.now().isoformat()}"],
                    )
                )

            logger.info(f"Extracted {len(artifacts)} artifacts")
            return artifacts

        except Exception as e:
            logger.error(f"Artifact extraction failed: {e}")
            return []

    def _summarize_file_list(self, file_list: List[Dict[str, Any]]) -> str:
        """Summarize file list for analysis"""
        total = len(file_list)
        summary = [f"Total files: {total}"]

        if file_list:
            # Group by extension
            extensions = {}
            for f in file_list:
                ext = f.get("extension", "unknown")
                extensions[ext] = extensions.get(ext, 0) + 1

            summary.append(f"File types: {extensions}")

        return "\n".join(summary)

    def _summarize_logs(self, log_data: List[Dict[str, Any]]) -> str:
        """Summarize log data"""
        if not log_data:
            return "No logs available"

        summary = [f"Total log entries: {len(log_data)}"]

        # Sample first few entries
        if len(log_data) > 0:
            summary.append("\nSample entries:")
            for entry in log_data[:5]:
                summary.append(str(entry))

        return "\n".join(summary)


# Example usage
if __name__ == "__main__":
    forensics = DigitalForensicsModule()

    # Test disk image analysis
    print("=" * 70)
    print("DISK IMAGE FORENSIC ANALYSIS")
    print("=" * 70)

    disk_metadata = {
        "image_format": "E01",
        "size_gb": 500,
        "hash": "abc123def456...",
        "acquisition_date": "2025-01-15",
        "file_system": "NTFS",
    }

    file_list = [
        {
            "name": "confidential.xlsx",
            "path": "/Users/employee/Documents",
            "modified": "2025-01-14 23:45:00",
            "extension": "xlsx",
            "deleted": True,
        },
        {
            "name": "suspicious.exe",
            "path": "/Users/employee/Downloads",
            "modified": "2025-01-14 22:30:00",
            "extension": "exe",
            "deleted": False,
        },
    ]

    disk_analysis = forensics.analyze_disk_image(disk_metadata, file_list)
    print(f"Analysis ID: {disk_analysis.analysis_id}")
    print(f"Incident Type: {disk_analysis.incident_type}")
    print(f"Timeline Events: {len(disk_analysis.timeline)}")
    print(f"Evidence Collected: {len(disk_analysis.evidence_collected)}")
    print(f"IOCs Found: {len(disk_analysis.indicators_of_compromise)}")
    print(f"\nKey Findings:")
    for finding in disk_analysis.key_findings[:3]:
        print(f"  - {finding}")

    # Test memory dump analysis
    print("\n" + "=" * 70)
    print("MEMORY DUMP ANALYSIS")
    print("=" * 70)

    memory_data = {
        "processes": [
            {"pid": 1234, "name": "svchost.exe"},
            {"pid": 5678, "name": "suspicious.exe"},
        ],
        "connections": [
            {"remote_ip": "192.168.1.1", "port": 443},
            {"remote_ip": "203.0.113.50", "port": 4444},
        ],
        "loaded_dlls": ["normal.dll", "injected.dll"],
    }

    memory_analysis = forensics.analyze_memory_dump(memory_data)
    print(f"Malware Detected: {memory_analysis.malware_detected}")
    print(f"Suspicious Processes: {len([p for p in memory_analysis.process_analysis if p.get('suspicious', False)])}")
    print(f"Network Connections: {len(memory_analysis.network_connections)}")
    print(f"Persistence Mechanisms: {len(memory_analysis.persistence_mechanisms)}")

    # Test timeline reconstruction
    print("\n" + "=" * 70)
    print("INCIDENT TIMELINE RECONSTRUCTION")
    print("=" * 70)

    log_data = [
        {
            "timestamp": "2025-01-14 22:00:00",
            "event": "User login",
            "user": "employee",
        },
        {
            "timestamp": "2025-01-14 22:30:00",
            "event": "File downloaded",
            "file": "suspicious.exe",
        },
        {
            "timestamp": "2025-01-14 23:00:00",
            "event": "Process started",
            "process": "suspicious.exe",
        },
        {
            "timestamp": "2025-01-14 23:30:00",
            "event": "Network connection",
            "destination": "203.0.113.50:4444",
        },
    ]

    incident_window = {
        "start": "2025-01-14 22:00:00",
        "end": "2025-01-15 00:00:00",
    }

    timeline = forensics.reconstruct_timeline(log_data, incident_window)
    print(f"Timeline Events: {len(timeline)}")
    for event in timeline[:3]:
        print(f"\n{event.timestamp} - {event.event_type}")
        print(f"  Significance: {event.significance}")
        print(f"  {event.description}")

    # Test artifact extraction
    print("\n" + "=" * 70)
    print("ARTIFACT EXTRACTION")
    print("=" * 70)

    artifacts = forensics.extract_artifacts(
        "Windows Registry",
        ["Run keys", "Recently used programs", "USB device history"],
    )
    print(f"Artifacts Extracted: {len(artifacts)}")
    for artifact in artifacts[:3]:
        print(f"\n{artifact.evidence_type}")
        print(f"  Source: {artifact.source}")
        print(f"  Relevance: {artifact.relevance_score:.2f}")
