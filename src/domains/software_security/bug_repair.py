"""
Bug Repair Module
Automated bug fixing and code refactoring using LLM
Based on Repilot and interactive feedback approaches from the research paper
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger
from .bug_detection import Bug, Language

logger = get_logger(__name__)


@dataclass
class Fix:
    """Bug fix"""
    fix_id: str
    bug_id: str
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float
    test_cases: List[str]


class BugRepairModule:
    """Bug Repair Module using LLM for automated bug fixing"""

    def __init__(self):
        self.llm_client = LLMClient()
        logger.info("Bug Repair Module initialized")

    def generate_fix(self, bug: Bug, code: str, language: Language) -> Fix:
        """Generate fix for a bug"""
        logger.info(f"Generating fix for {bug.bug_id}")

        prompt = f"""Fix this bug in {language.value} code:

**Bug:** {bug.name} ({bug.bug_type.value})
**Description:** {bug.description}
**Severity:** {bug.severity}

**Buggy Code:**
```{language.value}
{bug.code_snippet}
```

**Full Context:**
```{language.value}
{code}
```

Generate a complete fix that:
1. Resolves the bug completely
2. Maintains functionality
3. Follows best practices
4. Is well-documented

Provide JSON:
{{
    "fixed_code": "corrected code",
    "explanation": "what was changed and why",
    "confidence": float (0-1),
    "test_cases": ["test case code"]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1500)

            fix = Fix(
                fix_id=f"FIX-{hash(bug.bug_id) % 10000:04d}",
                bug_id=bug.bug_id,
                original_code=bug.code_snippet,
                fixed_code=result.get("fixed_code", ""),
                explanation=result.get("explanation", ""),
                confidence=result.get("confidence", 0.8),
                test_cases=result.get("test_cases", [])
            )

            logger.info(f"Fix generated: {fix.fix_id}")
            return fix

        except Exception as e:
            logger.error(f"Fix generation failed: {e}")
            raise

    def suggest_refactoring(self, code: str, language: Language) -> Dict[str, Any]:
        """Suggest code refactoring improvements"""
        logger.info("Suggesting refactorings")

        prompt = f"""Suggest refactoring improvements for this {language.value} code:

```{language.value}
{code}
```

Focus on:
- Extract method/function
- Simplify conditionals
- Remove duplication
- Improve naming
- Reduce complexity

Provide JSON with refactoring suggestions."""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1000)
            return result
        except Exception as e:
            logger.error(f"Refactoring suggestion failed: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    from .bug_detection import BugType, Severity

    repairer = BugRepairModule()

    sample_bug = Bug(
        bug_id="BUG-001",
        name="Division by Zero",
        bug_type=BugType.LOGIC_ERROR,
        description="Empty list causes division by zero",
        severity="HIGH",
        location={"file": "utils.py", "line": 4},
        code_snippet="return total / len(numbers)",
        fix_suggestion="Check for empty list before division",
        confidence=0.95
    )

    buggy_code = """
def calculate_average(numbers):
    total = sum(numbers)
    return total / len(numbers)
"""

    try:
        fix = repairer.generate_fix(sample_bug, buggy_code, Language.PYTHON)
        print(f"Fix ID: {fix.fix_id}")
        print(f"Fixed Code:\n{fix.fixed_code}")
        print(f"\nExplanation: {fix.explanation}")
    except Exception as e:
        print(f"Error: {e}")
