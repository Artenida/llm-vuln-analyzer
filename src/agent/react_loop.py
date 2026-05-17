"""
ReAct agent loop.

Builds a multi-section prompt for each function using the call graph:
  - target function source
  - callers (where input originates)
  - callees (where data flows to / sinks)

The prompt is language-agnostic and covers a broad vulnerability taxonomy
rather than being hardcoded to any specific codebase or framework.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from src.agent.state import AgentState
from src.agent.tools import ToolSet
from src.llm.client import LLMClient, VulnerabilityReport
from src.models import CodeSample

logger = logging.getLogger(__name__)


class ReActAgent:

    def __init__(self, llm: LLMClient, tools: Optional[ToolSet]):
        self.llm = llm
        self.tools = tools

    def run(
        self,
        sample: CodeSample,
        graph: Dict,
        all_samples: Optional[List[CodeSample]] = None,
    ) -> VulnerabilityReport:

        state = AgentState(current_function=sample.function_name)

        code_map: Dict[str, str] = {}
        if all_samples:
            for s in all_samples:
                node_id = f"{s.file_path}::{s.function_name}"
                code_map[node_id] = s.code
                code_map[s.function_name] = s.code

        callers: List[str] = []
        callees: List[str] = []

        if self.tools:
            hop = self.tools.trace_one_hop(sample.function_name, sample.file_path)
            callers = hop.get("callers", [])
            callees = hop.get("callees", [])

        state.memory["callers"] = callers
        state.memory["callees"] = callees
        state.reasoning_trace.append("graph_context_collected")

        prompt = self._build_prompt(sample, callers, callees, code_map)

        report = self.llm.analyze(sample, context_prompt=prompt)
        report.analysis_mode = "call_graph_context"

        state.reasoning_trace.append("analysis_complete")
        return report

    def _build_prompt(
        self,
        sample: CodeSample,
        callers: List[str],
        callees: List[str],
        code_map: Dict[str, str],
    ) -> str:

        lang = sample.language.value
        lines: List[str] = []

        lines.append(
            f"You are an expert security code reviewer. "
            f"The code is written in {lang}.\n\n"
            "YOUR TASK:\n"
            "Find security vulnerabilities that are DIRECTLY present in the "
            "TARGET FUNCTION shown below.\n\n"
            "SCOPING RULES — read carefully before analysing:\n"
            "  1. Only flag a vulnerability if the TARGET FUNCTION itself "
            "contains or directly causes it.\n"
            "  2. Do NOT flag the target because a CALLEE it calls has a "
            "vulnerability — the callee will be analysed separately.\n"
            "  3. Do NOT flag the target because a CALLER passes unsafe data "
            "into it — the caller is shown only to help you trace data origin.\n"
            "  4. A function that only reads input and delegates to another "
            "function (a pass-through / thin wrapper) is clean unless it "
            "introduces unsafe logic itself.\n"
            "  5. A function that passes user-controlled data INTO a sink "
            "(database call, system call, auth check, file write, etc.) "
            "without sanitising it first IS vulnerable, even if the sink "
            "is a callee.\n"
        )

        lines.append("=" * 60)
        lines.append(f"TARGET FUNCTION: {sample.function_name}")
        lines.append(f"File: {sample.file_path}")
        lines.append("=" * 60)
        lines.append(f"```{lang}")
        lines.append(sample.code)
        lines.append("```\n")

        internal_callers = [c for c in callers if not c.startswith("external::")]
        if internal_callers:
            lines.append("-" * 40)
            lines.append(
                f"CALLED BY ({len(internal_callers)} caller(s)) — "
                "trace where input data originates from.\n"
                "  NOTE: Do not flag these — use them only to understand "
                "what data enters the target."
            )
            lines.append("-" * 40)
            for caller_id in internal_callers:
                caller_code = (
                    code_map.get(caller_id)
                    or code_map.get(caller_id.split("::")[-1])
                )
                fn_name = caller_id.split("::")[-1]
                lines.append(f"\n> {fn_name}  [{caller_id}]")
                if caller_code:
                    lines.append(f"```{lang}")
                    lines.append(caller_code)
                    lines.append("```")
                else:
                    lines.append("  (source not available)")

        internal_callees = [c for c in callees if not c.startswith("external::")]
        external_callees = [c for c in callees if c.startswith("external::")]

        if internal_callees:
            lines.append("\n" + "-" * 40)
            lines.append(
                f"CALLS INTO ({len(internal_callees)} internal function(s)) — "
                "shown to identify downstream sinks.\n"
                "  NOTE: Do not flag vulnerabilities inside these — only flag "
                "if the TARGET passes tainted data into them without sanitising."
            )
            lines.append("-" * 40)
            for callee_id in internal_callees:
                callee_code = (
                    code_map.get(callee_id)
                    or code_map.get(callee_id.split("::")[-1])
                )
                fn_name = callee_id.split("::")[-1]
                lines.append(f"\n> {fn_name}  [{callee_id}]")
                if callee_code:
                    lines.append(f"```{lang}")
                    lines.append(callee_code)
                    lines.append("```")
                else:
                    lines.append("  (source not available)")

        if external_callees:
            lines.append("\n" + "-" * 40)
            lines.append("EXTERNAL / LIBRARY CALLS made by the target:")
            for ext in external_callees:
                lines.append(f"  - {ext.replace('external::', '')}")

        lines.append("\n" + "=" * 60)
        lines.append("VULNERABILITY CHECKLIST")
        lines.append("=" * 60)
        lines.append(
            "For each category below, assume NOT VULNERABLE unless you find direct"
            "evidence in the TARGET FUNCTION's code. A function that calls another"
            "function is NOT itself vulnerable for what that callee does. A function"
            "that receives a parameter and passes it along is NOT missing input"
            "validation — validation belongs at the boundary where the data enters"
            "the system. "
            "This list is not exhaustive — also report any other vulnerability "
            "you identify that is not listed here.\n"
        )

        lines.append(
            "INJECTION\n"
            "  - SQL injection: user input concatenated or interpolated directly "
            "into SQL strings without parameterisation or escaping.\n"
            "  - Command injection: user input passed to shell execution "
            "(exec, system, subprocess, eval, etc.) without sanitisation.\n"
            "  - LDAP / XPath / NoSQL injection: unsanitised input into query "
            "languages other than SQL.\n"
            "  - Template injection (SSTI): user input rendered inside a "
            "server-side template engine.\n"
            "  - Log injection: user-controlled strings written to logs without "
            "sanitisation, enabling log forging.\n"
            "  - HTML/JS injection (XSS): user input reflected into HTML or JS "
            "output without encoding.\n\n"

            "AUTHENTICATION & AUTHORISATION\n"
            "  - Broken authentication: using decode/parse instead of "
            "verify/validate for tokens (e.g. jwt.decode vs jwt.verify); "
            "accepting unverified credentials.\n"
            "  - Missing authentication: sensitive operations (password change, "
            "account delete, admin action, privilege assignment) performed "
            "without verifying the caller's identity INSIDE THIS FUNCTION. "
            "Note: if this function is a thin controller that simply calls a "
            "service, the check belongs in the service — do not flag the "
            "controller for the service's missing check.\n"
            "  - Hardcoded credentials or bypass: secret keys, passwords, or "
            "bypass conditions embedded directly in code.\n"
            "  - Privilege escalation / mass assignment: user-controlled fields "
            "(role, isAdmin, permissions, group) accepted without a whitelist "
            "and persisted or acted upon.\n"
            "  - Insecure direct object reference (IDOR): user-supplied ID used "
            "to access a resource without verifying the caller owns it.\n"
            "  - Missing authorisation check: function performs an action on "
            "behalf of a user without checking that user has permission.\n\n"

            "CRYPTOGRAPHY & SECRETS\n"
            "  - Weak or broken algorithm: use of MD5, SHA-1, DES, RC4, ECB "
            "mode, or other deprecated primitives for security purposes.\n"
            "  - Timing attack: password/token compared with == / === / strcmp "
            "instead of a constant-time comparison function.\n"
            "  - Hardcoded secret: API keys, JWT secrets, encryption keys, "
            "or passwords embedded as string literals.\n"
            "  - Insufficient randomness: use of Math.random(), rand(), or "
            "other non-CSPRNG sources for security-sensitive values.\n"
            "  - Insecure key storage: secrets logged, written to disk "
            "unencrypted, or transmitted in plaintext.\n\n"

            "INPUT VALIDATION & DATA HANDLING\n"
            "  - Missing input validation: user-supplied data used in a "
            "sensitive operation with no type, length, format, or range check.\n"
            "  - Path traversal: user input used to construct file system paths "
            "without canonicalisation or boundary checks.\n"
            "  - Unsafe deserialisation: untrusted data passed to deserialise / "
            "unpickle / JSON.parse with a reviver that executes code.\n"
            "  - Regular expression denial of service (ReDoS): user input "
            "matched against a vulnerable (exponential backtracking) regex.\n\n"

            "RESOURCE & ERROR HANDLING\n"
            "  - Information disclosure: stack traces, internal paths, or "
            "sensitive data returned to the caller in error responses.\n"
            "  - Resource exhaustion / DoS: no rate limiting, no size cap on "
            "uploads/payloads, or unbounded loops driven by user input.\n"
            "  - Race condition / TOCTOU: a check-then-act pattern where the "
            "state can change between check and act.\n"
            "  - Unhandled exception leaking sensitive data: catch blocks that "
            "expose internal error details to external callers.\n\n"

            "DEPENDENCY & CONFIGURATION\n"
            "  - Use of vulnerable or dangerous API: calling a known-unsafe "
            "function (e.g. eval, Function(), pickle.loads, yaml.load without "
            "Loader, gets, strcpy, sprintf without bounds).\n"
            "  - Insecure default configuration: security-relevant option left "
            "at an insecure default (SSL verify=False, debug=True in production, "
            "CORS allow-all, permissive file permissions).\n\n"

            "LANGUAGE-SPECIFIC PATTERNS\n"
            "  - Python: eval/exec with user input, pickle, yaml.load, "
            "format string injection via %-formatting or .format(), "
            "shell=True in subprocess calls.\n"
            "  - JavaScript/TypeScript: prototype pollution via object merge, "
            "eval/Function constructor with user data, innerHTML / "
            "document.write with user data, dangerouslySetInnerHTML.\n"
            "  - C/C++: buffer overflow (gets, strcpy, sprintf, scanf without "
            "width), integer overflow in size calculations, use-after-free, "
            "format string vulnerabilities (printf(user_input)).\n"
            "  - Java: XML external entity injection (XXE), unsafe reflection, "
            "Java object deserialisation (ObjectInputStream), JNDI injection.\n"
            "  - Go: integer conversion overflow, unsafe pointer usage, "
            "improper error handling hiding security failures.\n\n"

            "If the target function is clean against all of the above, "
            "set vulnerability_found: false. Do not invent findings.\n"
        )

        lines.append(
            "Respond with this EXACT JSON schema — no markdown, no extra text:\n"
            "{\n"
            '  "vulnerability_found": boolean,\n'
            '  "cwe_id": string (e.g. "CWE-89") or null,\n'
            '  "affected_lines": [integers — line numbers inside the TARGET '
            'FUNCTION only, 1-based relative to the file, not the function body],\n'
            '  "severity": "low" | "medium" | "high" | "critical" | null,\n'
            '  "explanation": string — what is wrong, why it is exploitable, '
            'and which specific variable or line causes it,\n'
            '  "patch_suggestion": string — concrete fix for the target '
            'function itself,\n'
            '  "confidence": float 0.0-1.0,\n'
            '  "hallucination_flag": boolean — true if uncertain whether '
            'this is a real exploitable vulnerability\n'
            "}"
        )

        return "\n".join(lines)