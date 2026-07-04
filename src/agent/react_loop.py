"""
ReAct agent loop — reason → act → observe cycle.

The agent starts with only the target function, then actively
calls tools to inspect callers/callees when it needs more context.
This prevents callee vulnerability bleed: the agent explicitly
decides whether a finding belongs to the target or a neighbour.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from src.agent.memory import AgentMemory
from src.agent.state import AgentState
from src.agent.tools import ToolSet
from src.llm.client import LLMClient, ReActStep, VulnerabilityReport
from src.models import CodeSample

logger = logging.getLogger(__name__)

MAX_STEPS = 5  # default; overridden by AgentConfig.max_steps


class ReActAgent:

    def __init__(self, llm: LLMClient, tools: Optional[ToolSet], max_steps: int = MAX_STEPS):
        self.llm = llm
        self.tools = tools
        self.max_steps = max_steps
        self.memory = AgentMemory()

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

        tool_history: List[dict] = []

        # Inject prior findings for callers/callees from this run's memory
        if self.tools:
            node_id = f"{sample.file_path}::{sample.function_name}"
            neighbour_ids = (
                self.tools.get_callers(sample.function_name, sample.file_path)
                + self.tools.get_callees(sample.function_name, sample.file_path)
            )
            prior_context = self.memory.get_context_for(neighbour_ids)
            if prior_context:
                tool_history.append({
                    "tool": "memory",
                    "args": {},
                    "result": prior_context,
                })

        for step in range(self.max_steps):
            logger.debug(
                "ReAct step %d/%d for %s", step + 1, self.max_steps, sample.function_name
            )

            react_step: ReActStep = self.llm.reason(
                sample=sample,
                tool_history=tool_history,
                start_line=sample.start_line or 0,
                end_line=sample.end_line or 0,
            )

            state.reasoning_trace.append(f"step_{step+1}: {react_step.reasoning}")

            if react_step.is_final:
                report = react_step.report
                # ── treat empty output as uncertain, retry once ───────────────
                if _is_empty_output(report):
                    logger.warning(
                        "Empty final answer for %s at step %d — retrying single-pass",
                        sample.function_name,
                        step + 1,
                    )
                    report = self.llm.analyze(sample)
                    report.analysis_mode = "react_loop_fallback"
                else:
                    report.analysis_mode = "react_loop"
                self._record(sample, report)
                return report

            tool_name = react_step.tool_name
            tool_args = react_step.tool_args or {}
            logger.debug("Tool call: %s(%s)", tool_name, tool_args)

            result = self._execute_tool(tool_name, tool_args, code_map)

            tool_history.append(
                {"tool": tool_name, "args": tool_args, "result": result}
            )
            state.tool_history.append(
                {
                    "step": step + 1,
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result,
                }
            )

        logger.warning(
            "ReAct max steps (%d) reached for %s", self.max_steps, sample.function_name
        )
        tool_history.append(
            {
                "tool": "system",
                "args": {},
                "result": f"Max steps ({self.max_steps}) reached. You MUST emit a final answer now.",
            }
        )
        react_step = self.llm.reason(
            sample=sample,
            tool_history=tool_history,
            start_line=sample.start_line or 0,
            end_line=sample.end_line or 0,
        )
        report = react_step.report or _make_timeout_report(sample)

        # ── retry if output is empty ──────────────────────────────────────────
        if _is_empty_output(report):
            logger.warning(
                "Empty ReAct output for %s — falling back to single-pass",
                sample.function_name,
            )
            report = self.llm.analyze(sample)
            report.analysis_mode = "react_loop_fallback"
        else:
            report.analysis_mode = "react_loop"

        self._record(sample, report)
        return report

    def _record(self, sample: CodeSample, report: VulnerabilityReport) -> None:
        node_id = f"{sample.file_path}::{sample.function_name}"
        self.memory.record(
            node_id=node_id,
            function_name=sample.function_name,
            vulnerability_found=report.vulnerability_found,
            cwe_id=report.cwe_id,
            severity=report.severity,
            summary=report.explanation[:120] if report.explanation else "",
        )

    def _execute_tool(
        self, tool_name: Optional[str], args: dict, code_map: Dict[str, str]
    ) -> str:
        if not self.tools or not tool_name:
            return "Tool unavailable — no call graph loaded."

        fn = args.get("function_name", "")

        try:
            if tool_name == "get_callees":
                result = self.tools.get_callees(fn)
                if not result:
                    return f"No callees found for '{fn}'."
                internal = [r for r in result if not r.startswith("external::")]
                external = [
                    r.replace("external::", "")
                    for r in result
                    if r.startswith("external::")
                ]
                parts = []
                if internal:
                    parts.append("Internal callees: " + ", ".join(internal))
                if external:
                    parts.append("External callees: " + ", ".join(external))
                return "\n".join(parts)

            elif tool_name == "get_callers":
                result = self.tools.get_callers(fn)
                if not result:
                    return f"No callers found for '{fn}' — may be an entry point."
                return "Callers: " + ", ".join(result)

            elif tool_name == "get_source":
                code = code_map.get(fn)
                if not code:
                    for k, v in code_map.items():
                        if k.endswith(f"::{fn}"):
                            code = v
                            break
                if code:
                    return f"Source of '{fn}':\n```\n{code}\n```"
                return f"Source not found for '{fn}'."

            elif tool_name == "is_entry_point":
                result = self.tools.is_entry_point(fn)
                return f"'{fn}' is_entry_point: {result}"

            elif tool_name == "get_node_info":
                info = self.tools.get_node_info(fn)
                if info:
                    return (
                        f"callers: {info['callers']}\n"
                        f"callees: {info['callees']}\n"
                        f"is_entry_point: {info['is_entry_point']}"
                    )
                return f"No node info for '{fn}'."

            else:
                return f"Unknown tool '{tool_name}'."

        except Exception as e:
            logger.warning("Tool %s failed: %s", tool_name, e)
            return f"Tool error: {e}"


def _make_timeout_report(sample: CodeSample) -> VulnerabilityReport:
    return VulnerabilityReport(
        function_name=sample.function_name,
        file_path=sample.file_path,
        language=sample.language.value,
        vulnerability_found=False,
        cwe_id=None,
        affected_lines=[],
        severity=None,
        explanation="ReAct loop reached max steps without a final answer.",
        patch_suggestion="",
        confidence=0.0,
        hallucination_flag=True,
        analysis_mode="react_loop",
        error="max_steps_exceeded",
    )


def _is_empty_output(report: VulnerabilityReport) -> bool:
    """
    True if the report is a silent failure:
    confidence=0, empty explanation, no vuln found.
    These cannot be trusted as genuine clean verdicts.
    """
    return (
        report is not None
        and not report.vulnerability_found
        and report.confidence == 0.0
        and not report.explanation
        and not report.error  # don't retry real errors
    )
