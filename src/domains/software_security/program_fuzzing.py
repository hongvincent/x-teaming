"""
Program Fuzzing Module
Test case generation and fuzz testing using LLM
Based on LLM-guided fuzzing approaches from the research paper
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger
from .vulnerability_detection import Language

logger = get_logger(__name__)


@dataclass
class TestCase:
    """Fuzz test case"""
    test_id: str
    input_data: Any
    expected_behavior: str
    test_type: str  # edge_case, random, mutation, etc.
    description: str


@dataclass
class CrashReport:
    """Crash report from fuzzing"""
    crash_id: str
    input_that_caused_crash: Any
    error_message: str
    stack_trace: str
    severity: str


class ProgramFuzzingModule:
    """Program Fuzzing Module using LLM for test generation"""

    def __init__(self):
        self.llm_client = LLMClient()
        logger.info("Program Fuzzing Module initialized")

    def generate_test_cases(
        self,
        function_signature: str,
        language: Language,
        count: int = 10
    ) -> List[TestCase]:
        """Generate fuzz test cases for a function"""
        logger.info(f"Generating {count} test cases for {function_signature}")

        prompt = f"""Generate {count} fuzz test cases for this {language.value} function:

```{language.value}
{function_signature}
```

Generate diverse test cases including:
- Edge cases (empty, null, max/min values)
- Boundary conditions
- Invalid inputs
- Random valid inputs
- Type mismatches

Provide JSON:
{{
    "test_cases": [
        {{
            "input_data": "input value",
            "expected_behavior": "what should happen",
            "test_type": "edge_case|random|mutation",
            "description": "test description"
        }}
    ]
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1500)

            test_cases = []
            for i, tc_data in enumerate(result.get("test_cases", [])):
                tc = TestCase(
                    test_id=f"TC-{i+1:03d}",
                    input_data=tc_data.get("input_data"),
                    expected_behavior=tc_data.get("expected_behavior", ""),
                    test_type=tc_data.get("test_type", "random"),
                    description=tc_data.get("description", "")
                )
                test_cases.append(tc)

            logger.info(f"Generated {len(test_cases)} test cases")
            return test_cases

        except Exception as e:
            logger.error(f"Test generation failed: {e}")
            return []

    def mutate_inputs(self, seed_inputs: List[Any]) -> List[Any]:
        """Mutate seed inputs for fuzzing"""
        logger.info(f"Mutating {len(seed_inputs)} seed inputs")

        prompt = f"""Mutate these seed inputs for fuzzing:

Seed inputs: {seed_inputs}

Generate mutations by:
- Flipping bits
- Changing types
- Adding/removing elements
- Boundary value testing

Provide 20 mutated inputs in JSON."""

        try:
            result = self.llm_client.complete_with_json(prompt)
            return result.get("mutated_inputs", [])
        except Exception as e:
            logger.error(f"Input mutation failed: {e}")
            return seed_inputs

    def detect_crashes(
        self,
        program: str,
        inputs: List[Any],
        language: Language
    ) -> List[CrashReport]:
        """Detect potential crashes from inputs"""
        logger.info(f"Testing {len(inputs)} inputs for crashes")

        prompt = f"""Analyze which inputs might crash this {language.value} program:

```{language.value}
{program}
```

Test inputs: {inputs[:10]}  # Show first 10

Identify inputs that could cause:
- Crashes
- Exceptions
- Hangs
- Memory errors

Provide JSON with crash reports."""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1000)
            crashes = []

            for i, crash_data in enumerate(result.get("crashes", [])):
                crash = CrashReport(
                    crash_id=f"CRASH-{i+1:03d}",
                    input_that_caused_crash=crash_data.get("input"),
                    error_message=crash_data.get("error", ""),
                    stack_trace=crash_data.get("stack_trace", ""),
                    severity=crash_data.get("severity", "MEDIUM")
                )
                crashes.append(crash)

            return crashes

        except Exception as e:
            logger.error(f"Crash detection failed: {e}")
            return []


# Example usage
if __name__ == "__main__":
    fuzzer = ProgramFuzzingModule()

    function = """
def divide_numbers(a: int, b: int) -> float:
    return a / b
"""

    print("=" * 70)
    print("PROGRAM FUZZING DEMONSTRATION")
    print("=" * 70)

    try:
        test_cases = fuzzer.generate_test_cases(function, Language.PYTHON, count=5)

        print(f"\nGenerated {len(test_cases)} test cases:\n")
        for tc in test_cases:
            print(f"{tc.test_id}: {tc.test_type}")
            print(f"  Input: {tc.input_data}")
            print(f"  Expected: {tc.expected_behavior}\n")

    except Exception as e:
        print(f"Error: {e}")
