"""The flow-level analysis pass: one LLM call per group of related functions.

Runs after the per-function pass and asks a different question. The per-function
pass asks "is this function wrong". This asks "do these functions disagree" -
because the defects it targets are ones where every individual function is
defensible and the combination is not.

Findings carry `analysis_mode="flow_pass"` so their cost and their accuracy can
be reported separately. That separation matters: this is the experimental stage,
and a negative result ("a flow pass at this model size finds 0 of the 13 in the
NEITHER bucket") is publishable given that a mature rule engine and a
per-function LLM agent both scored 0 there. It is only publishable if the flow
pass's own findings can be told apart from the rest.
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

import openai

from src.agent.flow_groups import FlowGroup
from src.llm.attribution import clean_implicated, normalize_node_id
from src.llm.client import LLMClient, VulnerabilityReport, _strip_fences, _normalize_cwe
from src.llm.pricing import TokenUsage, estimate_cost, extract_usage
from src.llm.taxonomy import CWE_TAXONOMY_PROMPT

logger = logging.getLogger(__name__)


FLOW_SYSTEM = """\
You are a security reviewer looking at a GROUP of functions that participate in
one workflow. Each of them has ALREADY been analysed on its own.

Do NOT repeat per-function defects. Report ONLY defects that exist BETWEEN these
functions — the ones that are invisible when each is read alone:
  - a value produced by one function and trusted by another without integrity
    protection (a reversible or unkeyed encoding used where a signature or MAC
    is needed, so anyone who can read this code can mint a valid value);
  - a check performed on one path into a sink and skipped on another path that
    reaches the same sink;
  - a required ordering not enforced across the group (pay then ship, verify
    then act, authenticate then authorise);
  - two functions that each assume the other performs a check, so neither does;
  - a value validated in one representation and used in another (normalised
    after the check rather than before).

If every defect you can see is contained within a single function, report
nothing: that is the other pass's job and duplicating it inflates the results.

""" + CWE_TAXONOMY_PROMPT + """
Respond with ONLY a valid JSON object, no markdown:
{
  "findings": [
    {
      "attributed_to": "<file>::<function>" — where the FIX belongs,
      "also_implicates": [other node_ids involved, at most 3],
      "cwe_id": string,
      "severity": "low" | "medium" | "high" | "critical",
      "explanation": string — name both ends of the defect and why the
                     combination is exploitable when neither function is alone,
      "patch_suggestion": string,
      "confidence": float 0.0–1.0
    }
  ]
}
An empty "findings" list is a valid and often correct answer.
"""


_GROUP_TEMPLATE = """\
=== WORKFLOW GROUP ({kind}) ===
{label}

Why these are grouped: {rationale}

{bodies}

=== TASK ===
Report only defects that exist BETWEEN these functions. If there are none,
return {{"findings": []}}.
"""


def format_group_prompt(group: FlowGroup, samples_by_id: Dict[str, object]) -> str:
    bodies = []
    for node_id in group.node_ids:
        sample = samples_by_id.get(node_id)
        if sample is None:
            continue
        bodies.append(
            f"--- {node_id}  (lines {sample.start_line}–{sample.end_line}) ---\n"
            f"```{sample.language.value}\n{sample.code}\n```"
        )
    return _GROUP_TEMPLATE.format(
        kind=group.kind,
        label=group.label,
        rationale=group.rationale,
        bodies="\n\n".join(bodies),
    )


class FlowPass:

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def run_group(
        self, group: FlowGroup, samples_by_id: Dict[str, object]
    ) -> List[VulnerabilityReport]:
        """Analyse one group. Returns zero or more reports, never raises."""
        prompt = format_group_prompt(group, samples_by_id)

        try:
            response = self.llm.client.chat.completions.create(
                model=self.llm.config.model,
                messages=[
                    {"role": "system", "content": FLOW_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            )
        except openai.OpenAIError as e:
            logger.error("Flow pass API error on group %s: %s", group.label, e)
            return []

        usage = extract_usage(response)
        cost = estimate_cost(self.llm.config.model, usage)
        self.llm._log_cost("flow_pass", usage, cost, group.label)

        raw = response.choices[0].message.content or ""
        try:
            data = json.loads(_strip_fences(raw))
        except json.JSONDecodeError as e:
            logger.warning("Flow pass JSON parse error for %s: %s", group.label, e)
            return []

        findings = data.get("findings") or []
        if not isinstance(findings, list):
            return []

        reports: List[VulnerabilityReport] = []
        for i, item in enumerate(findings):
            report = self._to_report(item, group, samples_by_id)
            if report is None:
                continue
            # Usage belongs to the group, not to any one finding. Attributing it
            # to the first keeps the run total exact without inventing a split.
            if i == 0:
                report.token_usage = usage
                report.cost_usd = cost
            reports.append(report)
        return reports

    def _to_report(
        self, item: dict, group: FlowGroup, samples_by_id: Dict[str, object]
    ) -> Optional[VulnerabilityReport]:
        if not isinstance(item, dict):
            return None

        attributed_to = normalize_node_id(item.get("attributed_to"))
        # A flow finding must say where the fix belongs. Without that it cannot
        # be scored against any row, and an unscoreable finding is not a result.
        target = self._resolve(attributed_to, group, samples_by_id)
        if target is None:
            logger.debug(
                "Flow finding on %s names no function in the group (%r) — dropped",
                group.label, item.get("attributed_to"),
            )
            return None

        sample = samples_by_id[target]
        return VulnerabilityReport(
            function_name=sample.function_name,
            file_path=sample.file_path,
            language=sample.language.value,
            vulnerability_found=True,
            cwe_id=_normalize_cwe(item.get("cwe_id")),
            affected_lines=[],
            severity=item.get("severity"),
            explanation=item.get("explanation", ""),
            patch_suggestion=item.get("patch_suggestion", ""),
            confidence=float(item.get("confidence", 0.7) or 0.7),
            hallucination_flag=False,
            attributed_to=attributed_to,
            also_implicates=clean_implicated(
                item.get("also_implicates"),
                attributed_to=attributed_to,
                target=group.label,
            ),
            analysis_mode="flow_pass",
            token_usage=TokenUsage(),
        )

    @staticmethod
    def _resolve(
        node_id: Optional[str], group: FlowGroup, samples_by_id: Dict[str, object]
    ) -> Optional[str]:
        """Map a model-supplied node_id onto a member of this group.

        Restricted to the group deliberately: a flow finding pointing at a
        function that was not in the prompt is not evidence about anything the
        model was shown.
        """
        if not node_id:
            return None
        if node_id in group.node_ids and node_id in samples_by_id:
            return node_id
        wanted = node_id.rpartition("::")[2] or node_id
        for member in group.node_ids:
            if member.rpartition("::")[2] == wanted and member in samples_by_id:
                return member
        return None


def run_flow_pass(
    llm: LLMClient,
    groups: List[FlowGroup],
    samples: List,
    progress=None,
) -> List[VulnerabilityReport]:
    """Run every group. Returns all flow-pass findings across all groups."""
    samples_by_id = {
        f"{s.file_path}::{s.function_name}": s
        for s in samples
        if not getattr(s, "chunk_of", None)
    }
    flow = FlowPass(llm)

    out: List[VulnerabilityReport] = []
    for i, group in enumerate(groups, 1):
        if progress is not None:
            progress(i, len(groups), group)
        out.extend(flow.run_group(group, samples_by_id))
    return out
