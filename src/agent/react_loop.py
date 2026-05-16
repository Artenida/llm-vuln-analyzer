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

        # ── build a lookup: node_id / function_name → code ───────────────────
        code_map: Dict[str, str] = {}
        if all_samples:
            for s in all_samples:
                node_id = f"{s.file_path}::{s.function_name}"
                code_map[node_id] = s.code
                code_map[s.function_name] = s.code

        # ── get one-hop neighbours from graph ─────────────────────────────────
        callers: List[str] = []
        callees: List[str] = []

        if self.tools:
            hop = self.tools.trace_one_hop(sample.function_name, sample.file_path)
            callers = hop.get("callers", [])
            callees = hop.get("callees", [])

        state.memory["callers"] = callers
        state.memory["callees"] = callees
        state.reasoning_trace.append("graph_context_collected")

        # ── build the enriched prompt ─────────────────────────────────────────
        prompt = self._build_prompt(sample, callers, callees, code_map)

        report = self.llm.analyze(sample, context_prompt=prompt)
        report.analysis_mode = "call_graph_context"

        state.reasoning_trace.append("analysis_complete")
        return report

    # ─────────────────────────────────────────────────────────────────────────
    # Prompt builder
    # ─────────────────────────────────────────────────────────────────────────

    def _build_prompt(
        self,
        sample: CodeSample,
        callers: List[str],
        callees: List[str],
        code_map: Dict[str, str],
    ) -> str:

        lines: List[str] = []

        lines.append(
            f"You are a security analysis agent reviewing a {sample.language.value} codebase.\n"
            "Your task is to find security vulnerabilities in the TARGET FUNCTION below.\n"
            "You are also given its callers and callees so you can reason about the full data flow.\n"
        )

        # ── target function ───────────────────────────────────────────────────
        lines.append("=" * 60)
        lines.append(f"TARGET FUNCTION: {sample.function_name}")
        lines.append(f"File: {sample.file_path}")
        lines.append("=" * 60)
        lines.append(f"```{sample.language.value}")
        lines.append(sample.code)
        lines.append("```\n")

        # ── callers ───────────────────────────────────────────────────────────
        internal_callers = [c for c in callers if not c.startswith("external::")]
        if internal_callers:
            lines.append("─" * 40)
            lines.append(f"CALLED BY ({len(internal_callers)} callers) — where untrusted input may originate:")
            lines.append("─" * 40)
            for caller_id in internal_callers:
                caller_code = code_map.get(caller_id) or code_map.get(
                    caller_id.split("::")[-1]
                )
                fn_name = caller_id.split("::")[-1]
                lines.append(f"\n▶ {fn_name}  [{caller_id}]")
                if caller_code:
                    lines.append(f"```{sample.language.value}")
                    lines.append(caller_code)
                    lines.append("```")
                else:
                    lines.append("  (source not available)")

        # ── callees ───────────────────────────────────────────────────────────
        internal_callees = [c for c in callees if not c.startswith("external::")]
        external_callees = [c for c in callees if c.startswith("external::")]

        if internal_callees:
            lines.append("\n" + "─" * 40)
            lines.append(f"CALLS INTO ({len(internal_callees)} internal) — downstream sinks:")
            lines.append("─" * 40)
            for callee_id in internal_callees:
                callee_code = code_map.get(callee_id) or code_map.get(
                    callee_id.split("::")[-1]
                )
                fn_name = callee_id.split("::")[-1]
                lines.append(f"\n▶ {fn_name}  [{callee_id}]")
                if callee_code:
                    lines.append(f"```{sample.language.value}")
                    lines.append(callee_code)
                    lines.append("```")
                else:
                    lines.append("  (source not available)")

        if external_callees:
            lines.append("\n" + "─" * 40)
            lines.append("EXTERNAL CALLS (library/runtime):")
            for ext in external_callees:
                lines.append(f"  • {ext.replace('external::', '')}")

        # ── instructions ──────────────────────────────────────────────────────
        lines.append("\n" + "=" * 60)
        lines.append("ANALYSIS INSTRUCTIONS")
        lines.append("=" * 60)
        lines.append(
            "Consider the FULL DATA FLOW:\n"
            "  1. What data enters this function from its callers?\n"
            "  2. Is that data validated or sanitized before reaching sensitive operations?\n"
            "  3. Does this function pass tainted data into its callees (SQL, auth, crypto)?\n"
            "  4. Are there vulnerabilities only visible when you see the call chain?\n\n"
            "Common patterns to check:\n"
            "  • SQL injection — string concatenation before fakeDb.execute / any DB call\n"
            "  • Broken auth — jwt.decode() instead of jwt.verify(), missing checks\n"
            "  • Mass assignment — user-controlled fields like 'role' passed directly\n"
            "  • Hardcoded secrets — bypass codes, fixed credentials\n"
            "  • Missing validation — passwords, emails, input not checked before use\n"
            "  • Timing attacks — == comparison for passwords/tokens\n"
            "  • Rate limit bypass — trusting x-forwarded-for header directly\n"
            "  • Privilege escalation — user input controlling role/permission fields\n"
        )

        lines.append(
            "Respond with this EXACT JSON schema, no markdown, no extra text:\n"
            "{\n"
            '  "vulnerability_found": boolean,\n'
            '  "cwe_id": string or null,\n'
            '  "affected_lines": [list of integers],\n'
            '  "severity": "low" | "medium" | "high" | "critical" | null,\n'
            '  "explanation": string,\n'
            '  "patch_suggestion": string,\n'
            '  "confidence": float between 0.0 and 1.0,\n'
            '  "hallucination_flag": boolean\n'
            "}"
        )

        return "\n".join(lines)