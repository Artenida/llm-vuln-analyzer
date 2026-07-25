"""
Patch generation.
Calls the LLM with (original_code, explanation, cwe_id) and returns a unified diff.
Generation only — does not touch disk or apply anything. See PatchValidator for that.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import openai

from src.llm.cost_ledger import CostLedger
from src.llm.pricing import TokenUsage, estimate_cost, extract_usage

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    unified_diff: str
    error: Optional[str] = None
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    cost_usd: Optional[float] = None


_PATCH_SYSTEM = (
    "You are a secure code-patching assistant. Given a vulnerable function, an "
    "explanation of the vulnerability, and its CWE, produce a minimal fix as a "
    "unified diff. Respond ONLY with the unified diff — no markdown fences, no "
    "prose, no explanation."
)

_PATCH_USER_TEMPLATE = """\
Function: {function_name}
Language: {language}
CWE: {cwe_id}

VULNERABILITY EXPLANATION:
{explanation}

SUGGESTED FIX DIRECTION:
{patch_suggestion}

ORIGINAL CODE:
```{language}
{code}
```

Produce a unified diff that patches ONLY the vulnerability described above.
Rules:
- Output format must be a standard unified diff, e.g.:
    --- a/{function_name}
    +++ b/{function_name}
    @@ -<start>,<count> +<start>,<count> @@
     context line
    -removed line
    +added line
- Context and removed lines must match the ORIGINAL CODE exactly, line for line.
- Keep the diff minimal — do not rewrite or reformat lines that don't need to change.
- Do not change the function's public signature/behavior beyond the security fix.
- Output ONLY the diff text. No markdown fences, no commentary.
"""


class PatchGenerator:

    def __init__(
        self,
        api_key: str,
        model: str = "o4-mini",
        api_key_alias: str = "default",
        cost_ledger: Optional[CostLedger] = None,
        run_id: Optional[str] = None,
        dataset: Optional[str] = None,
    ):
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY is required for patch generation.")
        self.model = model
        self.client = openai.OpenAI(api_key=api_key)
        self.api_key_alias = api_key_alias
        self.cost_ledger = cost_ledger
        self.run_id = run_id
        self.dataset = dataset

    def generate(
        self,
        code: str,
        explanation: str,
        cwe_id: Optional[str],
        function_name: str,
        language: str,
        patch_suggestion: str = "",
    ) -> PatchResult:
        prompt = _PATCH_USER_TEMPLATE.format(
            function_name=function_name,
            language=language,
            cwe_id=cwe_id or "unknown",
            explanation=explanation or "(none provided)",
            patch_suggestion=patch_suggestion or "(none provided)",
            code=code,
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": _PATCH_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            )
            usage = extract_usage(response)
            cost_usd = estimate_cost(self.model, usage)
            if self.cost_ledger is not None:
                self.cost_ledger.record(
                    provider="openai",
                    api_key_alias=self.api_key_alias,
                    model=self.model,
                    phase="patch_generation",
                    usage=usage,
                    cost_usd=cost_usd,
                    run_id=self.run_id,
                    dataset=self.dataset,
                    function_name=function_name,
                )

            raw = response.choices[0].message.content or ""
            diff = _strip_fences(raw)
            if not diff.strip():
                return PatchResult(unified_diff="", error="empty_llm_response", token_usage=usage, cost_usd=cost_usd)
            return PatchResult(unified_diff=diff, token_usage=usage, cost_usd=cost_usd)
        except openai.OpenAIError as e:
            logger.error("OpenAI API error during patch generation: %s", e)
            # the call failed before returning usage — $0, not unknown cost
            return PatchResult(unified_diff="", error=f"api_error: {e}", cost_usd=0.0)


def _strip_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(l for l in lines if not l.startswith("```")).strip()
    return text
