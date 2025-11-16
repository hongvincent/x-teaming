"""
Software & System Security Domain
Comprehensive software security analysis modules
"""

from .software_security_agent import SoftwareSecurityAgent
from .vulnerability_detection import (
    VulnerabilityDetectionModule,
    Vulnerability,
    VulnerabilityReport,
    Language,
    Severity
)
from .vulnerability_repair import (
    VulnerabilityRepairModule,
    Patch,
    RepairReport,
    RepairStrategy
)
from .bug_detection import (
    BugDetectionModule,
    Bug,
    BugReport,
    BugType
)
from .bug_repair import (
    BugRepairModule,
    Fix
)
from .program_fuzzing import (
    ProgramFuzzingModule,
    TestCase,
    CrashReport
)
from .reverse_engineering import (
    ReverseEngineeringModule,
    DecompiledCode,
    BinaryAnalysis
)
from .malware_detection import (
    MalwareDetectionModule,
    MalwareReport,
    MalwareFamily,
    MalwareType
)
from .system_log_analysis import (
    SystemLogAnalysisModule,
    LogAnomaly,
    LogAnalysisReport
)

__all__ = [
    # Main Agent
    "SoftwareSecurityAgent",

    # Vulnerability Detection
    "VulnerabilityDetectionModule",
    "Vulnerability",
    "VulnerabilityReport",
    "Language",
    "Severity",

    # Vulnerability Repair
    "VulnerabilityRepairModule",
    "Patch",
    "RepairReport",
    "RepairStrategy",

    # Bug Detection
    "BugDetectionModule",
    "Bug",
    "BugReport",
    "BugType",

    # Bug Repair
    "BugRepairModule",
    "Fix",

    # Program Fuzzing
    "ProgramFuzzingModule",
    "TestCase",
    "CrashReport",

    # Reverse Engineering
    "ReverseEngineeringModule",
    "DecompiledCode",
    "BinaryAnalysis",

    # Malware Detection
    "MalwareDetectionModule",
    "MalwareReport",
    "MalwareFamily",
    "MalwareType",

    # System Log Analysis
    "SystemLogAnalysisModule",
    "LogAnomaly",
    "LogAnalysisReport",
]
