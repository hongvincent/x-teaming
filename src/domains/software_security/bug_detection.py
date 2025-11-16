"""
Bug Detection Module
Identifies logic errors, code smells, and functional bugs using LLM
Based on contrastive learning and CodeBERT approaches from the research paper
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger
from .vulnerability_detection import Language

logger = get_logger(__name__)


class BugType(Enum):
    """Types of bugs"""
    LOGIC_ERROR = "logic_error"
    NULL_POINTER = "null_pointer"
    RESOURCE_LEAK = "resource_leak"
    RACE_CONDITION = "race_condition"
    INFINITE_LOOP = "infinite_loop"
    OFF_BY_ONE = "off_by_one"
    TYPE_ERROR = "type_error"
    CONCURRENCY_BUG = "concurrency_bug"
    CODE_SMELL = "code_smell"


@dataclass
class Bug:
    """Detected bug"""
    bug_id: str
    name: str
    bug_type: BugType
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    location: Dict[str, Any]
    code_snippet: str
    fix_suggestion: str
    confidence: float


@dataclass
class BugReport:
    """Bug detection report"""
    report_id: str
    total_bugs: int
    bugs_by_type: Dict[BugType, int]
    bugs: List[Bug]
    code_quality_score: float
    summary: str


class BugDetectionModule:
    """
    Bug Detection Module using LLM
    Detects logic errors, code smells, and functional bugs
    """

    def __init__(self):
        """Initialize bug detection module"""
        self.llm_client = LLMClient()
        logger.info("Bug Detection Module initialized")

    def detect_bugs(
        self,
        code: str,
        language: Language,
        filename: Optional[str] = None
    ) -> BugReport:
        """
        Detect bugs in code

        Args:
            code: Source code to analyze
            language: Programming language
            filename: Optional filename

        Returns:
            BugReport: Comprehensive bug report
        """
        logger.info(f"Detecting bugs in {language.value} code")

        system_message = f"""You are an expert code reviewer for {language.value}.
Identify bugs, logic errors, and code quality issues.
Focus on functional correctness and best practices."""

        prompt = f"""Analyze this {language.value} code for bugs and issues:

```{language.value}
{code}
```

Identify ALL bugs including:
1. Logic errors and incorrect algorithms
2. Null pointer/reference errors
3. Resource leaks (memory, file handles, etc.)
4. Race conditions and concurrency bugs
5. Infinite loops or performance issues
6. Off-by-one errors
7. Type mismatches
8. Code smells and anti-patterns

For each bug found, provide in JSON format:
{{
    "bugs": [
        {{
            "name": "bug name",
            "bug_type": "logic_error|null_pointer|resource_leak|race_condition|infinite_loop|off_by_one|type_error|concurrency_bug|code_smell",
            "description": "detailed description",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "line_number": line where bug occurs,
            "code_snippet": "the buggy code",
            "fix_suggestion": "how to fix it",
            "confidence": float (0-1)
        }}
    ],
    "code_quality_score": float (0-100),
    "summary": "overall code quality assessment"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt,
                system_message=system_message,
                max_tokens=2500
            )

            # Parse bugs
            bugs = []
            bugs_by_type = {}

            for i, bug_data in enumerate(result.get("bugs", [])):
                bug_type = BugType(bug_data.get("bug_type", "code_smell"))

                bug = Bug(
                    bug_id=f"BUG-{i+1:03d}",
                    name=bug_data.get("name", "Unknown Bug"),
                    bug_type=bug_type,
                    description=bug_data.get("description", ""),
                    severity=bug_data.get("severity", "MEDIUM"),
                    location={
                        "file": filename or "unknown",
                        "line": bug_data.get("line_number", 0)
                    },
                    code_snippet=bug_data.get("code_snippet", ""),
                    fix_suggestion=bug_data.get("fix_suggestion", ""),
                    confidence=bug_data.get("confidence", 0.8)
                )
                bugs.append(bug)

                # Count by type
                bugs_by_type[bug_type] = bugs_by_type.get(bug_type, 0) + 1

            report = BugReport(
                report_id=f"BUGRPT-{hash(code) % 10000:04d}",
                total_bugs=len(bugs),
                bugs_by_type=bugs_by_type,
                bugs=bugs,
                code_quality_score=result.get("code_quality_score", 50.0),
                summary=result.get("summary", "")
            )

            logger.info(f"Bug detection complete: {len(bugs)} bugs found")
            return report

        except Exception as e:
            logger.error(f"Bug detection failed: {e}")
            raise

    def find_code_smells(self, code: str, language: Language) -> List[Dict[str, Any]]:
        """
        Find code smells and anti-patterns

        Args:
            code: Source code
            language: Programming language

        Returns:
            List[Dict]: List of code smells found
        """
        logger.info("Finding code smells")

        system_message = """You are a code quality expert.
Identify code smells, anti-patterns, and maintainability issues."""

        prompt = f"""Find code smells in this {language.value} code:

```{language.value}
{code}
```

Look for:
- Long methods/functions
- Duplicated code
- Large classes
- Long parameter lists
- Magic numbers
- Dead code
- Unnecessary complexity

Respond in JSON:
{{
    "smells": [
        {{
            "name": "smell name",
            "location": "where it occurs",
            "impact": "maintainability|readability|performance",
            "suggestion": "how to fix"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            return result.get("smells", [])
        except Exception as e:
            logger.error(f"Code smell detection failed: {e}")
            return []

    def analyze_control_flow(self, code: str, language: Language) -> Dict[str, Any]:
        """
        Analyze control flow for potential issues

        Args:
            code: Source code
            language: Programming language

        Returns:
            Dict: Control flow analysis
        """
        logger.info("Analyzing control flow")

        system_message = """You are a static analysis expert.
Analyze control flow for unreachable code, infinite loops, and logic errors."""

        prompt = f"""Analyze control flow in this {language.value} code:

```{language.value}
{code}
```

Check for:
- Unreachable code
- Infinite loops
- Missing return statements
- Improper exception handling
- Complex branching

Provide JSON:
{{
    "issues": [
        {{
            "type": "issue type",
            "description": "what's wrong",
            "location": "line number",
            "severity": "HIGH|MEDIUM|LOW"
        }}
    ],
    "complexity_score": float (1-10)
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, system_message=system_message)
            return result
        except Exception as e:
            logger.error(f"Control flow analysis failed: {e}")
            return {"issues": [], "complexity_score": 0}


# Example usage
if __name__ == "__main__":
    detector = BugDetectionModule()

    buggy_code = """
def calculate_average(numbers):
    total = 0
    for num in numbers:
        total += num
    return total / len(numbers)  # Division by zero if empty

def process_data(data):
    result = []
    for i in range(len(data)):
        if data[i] > 0:
            result.append(data[i] * 2)
        else:
            result.append(data[i] / 0)  # Division by zero
    return result

def find_user(users, target_id):
    for user in users:
        if user.id == target_id:
            return user
    # Missing return statement for not found case
"""

    print("=" * 70)
    print("BUG DETECTION DEMONSTRATION")
    print("=" * 70)

    try:
        report = detector.detect_bugs(buggy_code, Language.PYTHON, "math_utils.py")

        print(f"\nReport ID: {report.report_id}")
        print(f"Total Bugs: {report.total_bugs}")
        print(f"Code Quality Score: {report.code_quality_score}/100")
        print(f"\nSummary: {report.summary}")

        print(f"\nBugs by Type:")
        for bug_type, count in report.bugs_by_type.items():
            print(f"  {bug_type.value}: {count}")

        print(f"\nDetailed Bugs:")
        for bug in report.bugs[:3]:
            print(f"\n  {bug.bug_id}: {bug.name}")
            print(f"  Type: {bug.bug_type.value}")
            print(f"  Severity: {bug.severity}")
            print(f"  Description: {bug.description}")
            print(f"  Fix: {bug.fix_suggestion}")

    except Exception as e:
        print(f"Error: {e}")
