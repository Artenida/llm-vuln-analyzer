"""
LLM client.
Two modes:
  analyze()  — single-pass vulnerability report (used without --react)
  reason()   — one ReAct step: returns either a tool call or a final report
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

import openai

from src.config import LLMConfig
from src.models import CodeSample

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Output types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityReport:
    function_name: Optional[str]
    file_path: Optional[str]
    language: str
    vulnerability_found: bool
    cwe_id: Optional[str]
    affected_lines: list[int]
    severity: Optional[str]
    explanation: str
    patch_suggestion: str
    confidence: float
    hallucination_flag: bool
    analysis_mode: str = "call_graph_context"
    error: Optional[str] = None
    unified_diff: str = ""
    patch_valid: Optional[bool] = None
    patch_error: Optional[str] = None


@dataclass
class ReActStep:
    """One step returned by reason(). Either a tool call or a final answer."""
    is_final: bool
    # if is_final=True
    report: Optional[VulnerabilityReport] = None
    # if is_final=False
    tool_name: Optional[str] = None      # e.g. "get_callees"
    tool_args: Optional[dict] = None     # e.g. {"function_name": "findById"}
    reasoning: Optional[str] = None      # agent's scratchpad thought


_SAFE_REPORT = VulnerabilityReport(
    function_name=None, file_path=None, language="unknown",
    vulnerability_found=False, cwe_id=None, affected_lines=[],
    severity=None,
    explanation="Parse error — could not read LLM response.",
    patch_suggestion="", confidence=0.0, hallucination_flag=True,
    error="json_parse_error",
)

# ─────────────────────────────────────────────────────────────────────────────
# Prompts
# ─────────────────────────────────────────────────────────────────────────────

_ANALYSIS_SYSTEM = (
    "You are a security-focused code reviewer. "
    "Respond ONLY with a valid JSON object. "
    "Do not include markdown, prose, or text outside the JSON."
)

_REACT_SYSTEM = """\
You are a security analysis agent operating in a ReAct loop.
Each turn you receive the current state and must respond with exactly ONE of:

Option A — call a tool to gather more information:
{
  "action": "tool",
  "tool": "<tool_name>",
  "args": { <tool arguments> },
  "thought": "<one sentence reasoning>"
}

Option B — emit the final vulnerability report when you have enough information:
{
  "action": "final",
  "thought": "<one sentence final reasoning>",
  "vulnerability_found": boolean,
  "cwe_id": string or null,
  "affected_lines": [list of integers — file-relative line numbers in TARGET only],
  "severity": "low" | "medium" | "high" | "critical" | null,
  "explanation": string,
  "patch_suggestion": string,
  "confidence": float 0.0–1.0 — probability that a vulnerability EXISTS.
               MUST be > 0.5 when vulnerability_found is true.
               MUST be < 0.5 when vulnerability_found is false.
               0.9+ means near-certain exploit; 0.1 means near-certain clean.,
  "hallucination_flag": boolean
}

Available tools:
  get_callees(function_name)    — returns list of functions this function calls
  get_callers(function_name)    — returns list of functions that call this function
  get_source(function_name)     — returns source code of a specific function
  is_entry_point(function_name) — returns true if this is an HTTP handler / route
  get_taint_path(function_name) — traces user-controlled data from HTTP entry points
                                   through this function to dangerous sinks (SQL, shell, etc.)
                                   Use this when you suspect an injection or flow-based vuln
  get_node_info(function_name)  — returns full metadata including taint_source / taint_sink flags

Rules:
- Start by reading the target function code provided in the state.
- Use tools ONLY when you need information not already in the state.
- Do NOT flag a vulnerability because a CALLEE has it — use get_callees + get_source
  to inspect the callee and attribute findings to the correct function.
- Do NOT flag a controller that only delegates — verify with get_callers if needed.
- A config.X reference is NOT a hardcoded secret — it reads from configuration.
- Emit "final" as soon as you have enough evidence. Max steps is enforced externally.
- Respond ONLY with valid JSON matching Option A or Option B. No markdown.

 - A function that RECEIVES an already-constructed SQL/command string and
    executes it (e.g. a db.execute(query) wrapper) is NOT vulnerable for
    injection — the vulnerability is in the CALLER that builds the string.
    Use get_callers + get_source to find and flag the builder, not the executor.

CWE assignment rules — use the MOST SPECIFIC applicable CWE:
  CWE-89   SQL/NoSQL built by string concat or template literal interpolation
  CWE-347  JWT or token accepted without signature verification (jwt.decode vs jwt.verify)
  CWE-798  Hardcoded credentials, secrets, API keys, or static bypass codes
  CWE-20   Security decision based on a client-supplied header (e.g. X-Forwarded-For for IP)
  CWE-306  Security step skipped (e.g. current-password not verified before change)
  CWE-208  Non-constant-time comparison of secrets (timing attack)
  CWE-269  Role or privilege accepted directly from user-controlled input
  NOTE: CWE-290 is for relay/reflection spoofing attacks — do NOT use it for static bypass codes
        or hardcoded admin secrets; use CWE-798 instead.

Severity rules — apply consistently for the same CWE:
  high     CWE-89, CWE-347, CWE-798
  medium   CWE-20, CWE-208, CWE-269, CWE-306
  low      Informational / defence-in-depth only
  Deviate from these defaults ONLY when you can state a concrete amplifying or
  mitigating factor (e.g. "no authentication required to reach this endpoint").
"""

_REACT_STATE_TEMPLATE = """\
=== TARGET FUNCTION ===
Name: {function_name}
File: {file_path}
Lines: {start_line}–{end_line}

```{language}
{code}
```

=== TOOL HISTORY ===
{tool_history}

=== TASK ===
Determine if the TARGET FUNCTION contains a security vulnerability.
Remember: only flag what is directly in the target — not in its callers or callees.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────

class LLMClient:

    def __init__(self, config: LLMConfig):
        self.config = config
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY environment variable is not set.")
        self.client = openai.OpenAI(api_key=api_key)

    # ── single-pass analysis ──────────────────────────────────────────────────

    def analyze(
        self,
        sample: CodeSample,
        context_prompt: str,
    ) -> VulnerabilityReport:
        user_message = context_prompt
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                #max_tokens=self.config.max_tokens,
                #temperature=self.config.temperature,
                messages=[
                    {"role": "system", "content": _ANALYSIS_SYSTEM},
                    {"role": "user",   "content": user_message},
                ],
            )
            raw = response.choices[0].message.content or ""
            return self._parse_report(raw, sample)
        except openai.OpenAIError as e:
            logger.error("OpenAI API error: %s", e)
            r = _make_safe(sample)
            r.error = f"api_error: {e}"
            return r

    # ── ReAct step ────────────────────────────────────────────────────────────

    def reason(
        self,
        sample: CodeSample,
        tool_history: list[dict],
        start_line: int = 0,
        end_line: int = 0,
    ) -> ReActStep:
        """
        One ReAct reasoning step. Returns either a tool call or a final report.
        tool_history is a list of {"tool": ..., "args": ..., "result": ...} dicts.
        """
        history_text = _format_tool_history(tool_history)

        state_message = _REACT_STATE_TEMPLATE.format(
            function_name=sample.function_name,
            file_path=sample.file_path,
            start_line=start_line or sample.start_line or "?",
            end_line=end_line or sample.end_line or "?",
            language=sample.language.value,
            code=sample.code,
            tool_history=history_text or "(none yet)",
        )

        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                #max_tokens=self.config.max_tokens,
                #temperature=0.0,
                messages=[
                    {"role": "system", "content": _REACT_SYSTEM},
                    {"role": "user",   "content": state_message},
                ],
            )
            raw = response.choices[0].message.content or ""
            return self._parse_react_step(raw, sample)
        except openai.OpenAIError as e:
            logger.error("OpenAI API error in reason(): %s", e)
            return ReActStep(
                is_final=True,
                report=_make_error(sample, f"api_error: {e}"),
            )

    # ── parsers ───────────────────────────────────────────────────────────────

    def _parse_report(self, raw: str, sample: CodeSample) -> VulnerabilityReport:
        text = _strip_fences(raw)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning("JSON parse error: %s | raw: %.200s", e, raw)
            return _make_safe(sample)

        return VulnerabilityReport(
            function_name=sample.function_name,
            file_path=sample.file_path,
            language=sample.language.value,
            vulnerability_found=bool(data.get("vulnerability_found", False)),
            cwe_id=_normalize_cwe(data.get("cwe_id")),
            affected_lines=data.get("affected_lines", []),
            severity=data.get("severity"),
            explanation=data.get("explanation", ""),
            patch_suggestion=data.get("patch_suggestion", ""),
            confidence=float(data.get("confidence", 0.0)),
            hallucination_flag=bool(data.get("hallucination_flag", False)),
        )

    def _parse_react_step(self, raw: str, sample: CodeSample) -> ReActStep:
        text = _strip_fences(raw)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning("ReAct JSON parse error: %s | raw: %.200s", e, raw)
            return ReActStep(is_final=True, report=_make_safe(sample))

        action = data.get("action", "final")

        if action == "tool":
            return ReActStep(
                is_final=False,
                tool_name=data.get("tool"),
                tool_args=data.get("args", {}),
                reasoning=data.get("thought"),
            )

        # action == "final"
        report = VulnerabilityReport(
            function_name=sample.function_name,
            file_path=sample.file_path,
            language=sample.language.value,
            vulnerability_found=bool(data.get("vulnerability_found", False)),
            cwe_id=_normalize_cwe(data.get("cwe_id")),
            affected_lines=data.get("affected_lines", []),
            severity=data.get("severity"),
            explanation=data.get("explanation", ""),
            patch_suggestion=data.get("patch_suggestion", ""),
            confidence=float(data.get("confidence", 0.0)),
            hallucination_flag=bool(data.get("hallucination_flag", False)),
            analysis_mode="react_loop",
        )
        return ReActStep(
            is_final=True,
            report=report,
            reasoning=data.get("thought"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _strip_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(l for l in lines if not l.startswith("```")).strip()
    return text


def _make_safe(sample: CodeSample) -> VulnerabilityReport:
    r = VulnerabilityReport(
        function_name=sample.function_name,
        file_path=sample.file_path,
        language=sample.language.value,
        vulnerability_found=False, cwe_id=None, affected_lines=[],
        severity=None,
        explanation="Parse error — could not read LLM response.",
        patch_suggestion="", confidence=0.0, hallucination_flag=True,
        error="json_parse_error",
    )
    return r


def _make_error(sample: CodeSample, msg: str) -> VulnerabilityReport:
    r = _make_safe(sample)
    r.error = msg
    return r


def _format_tool_history(history: list[dict]) -> str:
    if not history:
        return ""
    lines = []
    for i, entry in enumerate(history, 1):
        tool = entry.get("tool", "?")
        args = json.dumps(entry.get("args", {}))
        result = entry.get("result", "")
        lines.append(f"Step {i}: {tool}({args})\nResult: {result}\n")
    return "\n".join(lines)

def _normalize_cwe(raw: str | None) -> str | None:
    """Normalize CWE to consistent 'CWE-NNN' format."""
    if not raw:
        return None
    s = str(raw).strip()
    # already correct
    if s.upper().startswith("CWE-"):
        return "CWE-" + s[4:]
    # bare number: "89" -> "CWE-89"
    if s.isdigit():
        return f"CWE-{s}"
    return s
