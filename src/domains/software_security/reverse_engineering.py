"""
Reverse Engineering Module
Binary analysis and decompilation using LLM
Based on DexBert and SYMC approaches from the research paper
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DecompiledCode:
    """Decompiled source code"""
    language: str
    code: str
    confidence: float
    functions: List[str]
    analysis: str


@dataclass
class BinaryAnalysis:
    """Binary analysis results"""
    file_type: str
    architecture: str
    entry_point: str
    imports: List[str]
    exports: List[str]
    strings: List[str]
    security_features: Dict[str, bool]


class ReverseEngineeringModule:
    """Reverse Engineering Module using LLM"""

    def __init__(self):
        self.llm_client = LLMClient()
        logger.info("Reverse Engineering Module initialized")

    def decompile_binary(self, binary_description: str) -> DecompiledCode:
        """Decompile binary code to high-level language"""
        logger.info("Decompiling binary")

        prompt = f"""Decompile this binary/assembly code:

```
{binary_description}
```

Provide:
1. High-level language equivalent (C/C++ preferred)
2. Identified functions and their purposes
3. Analysis of what the code does

JSON format:
{{
    "language": "C",
    "code": "decompiled source code",
    "confidence": float (0-1),
    "functions": ["list of function names"],
    "analysis": "what this code does"
}}"""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=2000)

            decomp = DecompiledCode(
                language=result.get("language", "C"),
                code=result.get("code", ""),
                confidence=result.get("confidence", 0.7),
                functions=result.get("functions", []),
                analysis=result.get("analysis", "")
            )

            logger.info(f"Decompilation complete (confidence: {decomp.confidence:.2f})")
            return decomp

        except Exception as e:
            logger.error(f"Decompilation failed: {e}")
            raise

    def extract_strings(self, binary_data: str) -> List[str]:
        """Extract strings from binary"""
        logger.info("Extracting strings from binary")

        prompt = f"""Extract meaningful strings from this binary data:

{binary_data[:500]}...

Focus on:
- URLs
- IP addresses
- File paths
- API keys
- Error messages
- Debug strings

Provide JSON with extracted strings."""

        try:
            result = self.llm_client.complete_with_json(prompt)
            return result.get("strings", [])
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return []

    def analyze_control_flow(self, assembly_code: str) -> Dict[str, Any]:
        """Analyze control flow from assembly"""
        logger.info("Analyzing control flow")

        prompt = f"""Analyze the control flow graph of this assembly code:

```asm
{assembly_code}
```

Identify:
- Basic blocks
- Branch targets
- Function calls
- Return paths
- Loops

Provide JSON with CFG analysis."""

        try:
            result = self.llm_client.complete_with_json(prompt, max_tokens=1500)
            return result
        except Exception as e:
            logger.error(f"CFG analysis failed: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    rev_eng = ReverseEngineeringModule()

    assembly = """
push ebp
mov ebp, esp
sub esp, 0x10
mov dword [ebp-4], 0
jmp check
loop:
    mov eax, [ebp-4]
    add eax, 1
    mov [ebp-4], eax
check:
    cmp dword [ebp-4], 10
    jl loop
leave
ret
"""

    print("=" * 70)
    print("REVERSE ENGINEERING DEMONSTRATION")
    print("=" * 70)

    try:
        decomp = rev_eng.decompile_binary(assembly)
        print(f"\nDecompiled Code ({decomp.language}):")
        print(decomp.code)
        print(f"\nAnalysis: {decomp.analysis}")
        print(f"Confidence: {decomp.confidence:.0%}")
    except Exception as e:
        print(f"Error: {e}")
