import os
import json
import re
from dataclasses import dataclass
from dotenv import load_dotenv
from openai import OpenAI
from src.preprocessing.data_loader import CodeSample

load_dotenv()

@dataclass
class VulnerabilityReport:
    vulnerability_found: bool
    cwe_id: str | None
    affected_lines: list[int]
    severity: str | None
    explanation: str
    patch_suggestion: str
    confidence: float
    hallucination_flag: bool
    raw_response: str        # always store the raw LLM output
    model_used: str

SYSTEM_PROMPT = """You are a security-focused code reviewer with deep knowledge 
of the MITRE CWE taxonomy and Java security vulnerabilities.

Analyze the provided Java method for security vulnerabilities.
Be precise and conservative — only report what you can directly 
justify from the code. Do not speculate."""

OUTPUT_SCHEMA = """
Respond ONLY with a valid JSON object. No explanation before or after. 
No markdown fences. Just the raw JSON:

{
  "vulnerability_found": true or false,
  "cwe_id": "CWE-XX" or null,
  "affected_lines": [list of line numbers, or empty list],
  "severity": "low" or "medium" or "high" or "critical" or null,
  "explanation": "what is wrong and why, or why it is safe",
  "patch_suggestion": "concrete fix, or null if no vulnerability",
  "confidence": 0.0 to 1.0,
  "hallucination_flag": true if you are guessing, false if you are certain
}
"""

def build_user_prompt(sample: CodeSample) -> str:
    return f"""Analyze this Java method for security vulnerabilities.

### Method: `{sample.function_name}`
### CWE context: This file is from a dataset covering {sample.cwe_id} vulnerabilities.

```java
{sample.source_code}
```

{OUTPUT_SCHEMA}"""

def parse_response(raw: str) -> dict:
    """Parse LLM response into a dict, handling common formatting issues."""
    # Strip markdown fences if the model added them anyway
    clean = re.sub(r"```json|```", "", raw).strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        # Return a safe default if parsing fails
        return {
            "vulnerability_found": False,
            "cwe_id": None,
            "affected_lines": [],
            "severity": None,
            "explanation": "Failed to parse model response.",
            "patch_suggestion": None,
            "confidence": 0.0,
            "hallucination_flag": True,
        }

class LLMClient:
    def __init__(self, model: str = "gpt-4o-mini", max_tokens: int = 2000, temperature: float = 0):
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def analyze(self, sample: CodeSample) -> VulnerabilityReport:
        user_prompt = build_user_prompt(sample)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            raw = response.choices[0].message.content
        except Exception as e:
            print(f"API error for {sample.function_name}: {e}")
            return VulnerabilityReport(
                vulnerability_found=False,
                cwe_id=None,
                affected_lines=[],
                severity=None,
                explanation=f"API error: {str(e)}",
                patch_suggestion=None,
                confidence=0.0,
                hallucination_flag=True,
                raw_response=str(e),
                model_used=self.model,
            )

        parsed = parse_response(raw)
        return VulnerabilityReport(
            vulnerability_found=parsed.get("vulnerability_found", False),
            cwe_id=parsed.get("cwe_id"),
            affected_lines=parsed.get("affected_lines", []),
            severity=parsed.get("severity"),
            explanation=parsed.get("explanation", ""),
            patch_suggestion=parsed.get("patch_suggestion"),
            confidence=parsed.get("confidence", 0.0),
            hallucination_flag=parsed.get("hallucination_flag", False),
            raw_response=raw,
            model_used=self.model,
        )
