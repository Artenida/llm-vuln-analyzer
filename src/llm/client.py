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
 - If you see a comment of the exact form
    `/* --- nested method 'X' analyzed separately --- */` in place of a
    method body, that is expected and NOT obfuscated/incomplete/suspicious
    code — `X` is a nested method (e.g. a constructor's `this.foo = function
    () {...}`) extracted and analyzed independently under its own name.
    Do not flag the function containing this comment based on it, and do not
    treat the comment itself as evidence of anything. If you need to inspect
    `X`, call get_source(X) or get_callees/get_taint_path — and attribute
    any finding you make there to `X`, not to the function containing the
    comment.

CWE assignment rules — use the MOST SPECIFIC applicable CWE:
  CWE-89    SQL/NoSQL built by string concat or template literal interpolation
  CWE-347   JWT or token accepted without signature verification (jwt.decode vs jwt.verify)
  CWE-798   Hardcoded credentials, secrets, API keys, or static bypass codes
  CWE-20    Security decision based on a client-supplied header (e.g. X-Forwarded-For for IP)
  CWE-306   Security step skipped (e.g. current-password not verified before change)
  CWE-208   Non-constant-time comparison of secrets (timing attack)
  CWE-269   Role or privilege accepted directly from user-controlled input
  CWE-639   Object/resource fetched or mutated by a client-supplied id with no check that
            it belongs to the requesting user (IDOR / broken object-level authorization)
  CWE-862   A privileged or sensitive action (refund, delete, role change, admin-only op)
            performed with no check of the caller's role/permission at all
  CWE-841   A multi-step business workflow's required ordering is not enforced
            (e.g. shipping/fulfilling before payment is confirmed)
  CWE-915   Client-supplied fields merged wholesale into a stored record instead of only
            the fields that are meant to be user-editable (mass assignment)
  CWE-362   A business-state flag is read ("check"), then some work happens, then the
            flag is written ("act") — a concurrent request can pass the check before
            either write lands (e.g. a coupon/voucher redeemed twice)
  CWE-79    User-controlled input rendered into an HTML response in the wrong context
            (e.g. HTML-encoded but placed inside a <script> or URL/attribute context) — XSS
  CWE-95    User-controlled input passed to eval(), new Function(), vm.runInContext, or
            similar dynamic code execution (eval/code injection)
  CWE-1333  A regular expression with nested or overlapping quantifiers (e.g. `(a+)+`,
            `([0-9]+)+`) applied to user-controlled input — catastrophic backtracking (ReDoS)
  CWE-117   User-controlled input written to a log sink (console.log, a logger call) without
            sanitizing newlines/control characters first — log injection / CRLF forging
  CWE-521   A password/credential policy (regex or length/complexity check) that imposes
            insufficient requirements (e.g. any length, no character-class requirement)
  CWE-256   A password or credential stored or compared in plaintext instead of a salted
            hash, or logged/returned in plaintext
  NOTE: CWE-290 is for relay/reflection spoofing attacks — do NOT use it for static bypass codes
        or hardcoded admin secrets; use CWE-798 instead.

Severity rules — apply consistently for the same CWE:
  high     CWE-89, CWE-347, CWE-798, CWE-639, CWE-862, CWE-95, CWE-256
  medium   CWE-20, CWE-208, CWE-269, CWE-306, CWE-841, CWE-915, CWE-362, CWE-79,
           CWE-1333, CWE-117, CWE-521
  low      Informational / defence-in-depth only
  Deviate from these defaults ONLY when you can state a concrete amplifying or
  mitigating factor (e.g. "no authentication required to reach this endpoint",
  or "this stores the credential itself, not just a one-time comparison of it").

Business logic checklist — CWE-639/862/841/915/362 are NOT syntax patterns;
they only show up by checking what the function does against what it SHOULD
enforce. Use get_callers/get_source/get_node_info/get_taint_path (same tools
as above) to check, for entry points and any function that reads or mutates
a stored resource:
  - Attribution rule (same principle as the SQL builder/executor rule above):
    a low-level data-access function (a repository/DB wrapper that just looks
    up or writes a record by the id/object its CALLER passed in — e.g.
    findById, save, an ORM call) is NOT where CWE-639/862 belong. The
    authorization decision is the CALLER's responsibility — the function that
    decides WHICH id to fetch and WHETHER the requester may see/change it.
    Use get_callers + get_source to find that decision point and flag it (or
    its absence) there, not the storage accessor.
  - Is an id/key used to fetch or update a resource ever compared against the
    requesting user's own identity (e.g. `resource.userId === user.id`)? If
    the id comes from the client and there is no such comparison anywhere in
    this function or the path to it, that is CWE-639, not a clean read.
  - Does this function perform a privileged action (refund, delete, ban,
    change role/price) with NO check of the caller's role anywhere in it or
    its callers? That is CWE-862. A comment saying "admin only" is not a
    check — only code that reads and compares a role value counts.
  - Does this function skip a required prior step of a workflow (e.g. marks
    an order shipped/delivered without checking it was paid first)? That is
    CWE-841.
  - Does this function copy an entire client-supplied object/body into a
    stored record (spread, `Object.assign`, `.update(req.body)`) instead of
    picking only the fields a user should be allowed to set? That is CWE-915.
  - Does this function check a "used"/"locked"/"redeemed" flag, then do work,
    then set that flag afterwards — with no lock/transaction between the
    check and the write? That is CWE-362.
  Do NOT flag these speculatively. If the function already contains the
  matching check (an explicit ownership, role, status, or flag comparison
  before the sensitive action), it is clean — say so rather than guessing
  that a check might be missing elsewhere.
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
