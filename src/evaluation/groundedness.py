"""
Label-free scoring: is a finding supported by the program it is about?

`evaluate` asks whether a finding was correct, which needs an answer key and is
therefore only available on the five curated datasets. The checks here ask a
different and weaker question that needs no answer key at all: does the code the
finding describes actually look like that. A finding can pass every check and
still be wrong, but one that fails them is wrong about something verifiable —
it cites a line outside the function, names a data flow the call graph does not
contain, or classifies the defect with a CWE the prompt never offered.

Two uses:

  1. It measures hallucination externally. `hallucination_rate_on_flagged` reads
     a flag the model sets about itself, and on the juice-shop run that flag is
     0.000 on 109 findings, which is not a measurement of anything.
  2. It may work as a filter. If ungrounded findings turn out to be
     disproportionately false positives, they can be de-ranked on a codebase
     that has no ground truth, which is every real one. `cross_tabulate()`
     answers that against a scored run.

Every check returns PASS, FAIL or NOT_APPLICABLE, and a reason. Nothing here
consults the ground truth, and nothing here calls a model.
"""
from __future__ import annotations

import re
from typing import Optional

from src.llm.evidence_gate import FLOW_CWES

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"

# Every CWE the prompt offers. Read from the taxonomy text rather than
# maintained here, so this cannot drift from what the model was actually asked
# for — the drift that Stage 4 of the analysis quality plan had to repair.
_CWE_IN_TEXT = re.compile(r"CWE-\d+")


def taxonomy_cwes() -> frozenset:
    from src.llm.taxonomy import CWE_TAXONOMY_PROMPT

    return frozenset(_CWE_IN_TEXT.findall(CWE_TAXONOMY_PROMPT))


# "line 82", "lines 45-46", "line 45 and 46". Deliberately does not match bare
# numbers: an explanation saying "10 characters" is not citing a line.
_LINE_CITATION = re.compile(r"\blines?\s+(\d+)(?:\s*[-–to]+\s*(\d+))?", re.IGNORECASE)

# Backticked code spans, which is how the prompt asks for identifiers to be
# written. Anything with a space is prose in backticks, not a token.
_BACKTICKED = re.compile(r"`([^`\n]{2,60})`")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\(\))?$")


def _result(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason}


# ─────────────────────────────────────────────────────────────────────────────
# The checks
# ─────────────────────────────────────────────────────────────────────────────


def check_location(finding: dict, sample: Optional[dict]) -> dict:
    """G1 — every reported line falls inside the function that was analysed.

    A finding whose lines sit outside its own target is pointing at code it was
    not shown. The analyzer already clamps these, so a failure here means the
    clamp did not fire, not that the model was merely imprecise.
    """
    lines = [int(n) for n in (finding.get("affected_lines") or []) if isinstance(n, int)]
    if not lines:
        return _result(NOT_APPLICABLE, "finding reports no affected lines")
    if sample is None:
        return _result(NOT_APPLICABLE, "function not found in the extraction record")
    start, end = int(sample["start_line"]), int(sample["end_line"])
    outside = [n for n in lines if not (start <= n <= end)]
    if outside:
        return _result(FAIL, f"lines {outside} fall outside {start}-{end}")
    return _result(PASS, f"all reported lines inside {start}-{end}")


def check_line_citations(finding: dict, sample: Optional[dict]) -> dict:
    """G2 — line numbers named in the prose also fall inside the function.

    Separate from G1 because they come from different places: `affected_lines`
    is a structured field the pipeline post-processes, while the explanation is
    free text nothing has ever checked. A citation to a line the function does
    not contain is a fabricated detail, whatever the verdict turns out to be.
    """
    if sample is None:
        return _result(NOT_APPLICABLE, "function not found in the extraction record")
    text = finding.get("explanation") or ""
    cited = set()
    for m in _LINE_CITATION.finditer(text):
        cited.add(int(m.group(1)))
        if m.group(2):
            cited.add(int(m.group(2)))
    if not cited:
        return _result(NOT_APPLICABLE, "explanation cites no line numbers")
    start, end = int(sample["start_line"]), int(sample["end_line"])
    outside = sorted(n for n in cited if not (start <= n <= end))
    if outside:
        return _result(FAIL, f"explanation cites lines {outside}, function spans {start}-{end}")
    return _result(PASS, f"cited lines {sorted(cited)} all inside {start}-{end}")


def check_flow_source(finding: dict, node_id: Optional[str], node: Optional[dict],
                      reachable: frozenset) -> dict:
    """G3 — a flow CWE is reported on code that untrusted data can actually reach.

    An injection is untrusted data arriving at a dangerous sink, so a flow CWE
    on a function no request can reach is unsupported however dangerous the sink
    looks. That is the CWE-117 failure the evidence gate was built for: the
    values were config entries and internal arguments, not user input.

    The check is deliberately structural. An earlier version tried to resolve
    the model's prose `declared_source` ("req.body.email in the login handler")
    to a graph node by name, and matched English words that happen to be
    function names in this codebase — `from`, `String`, `hash` — producing
    failures that said more about the matcher than the finding. Reachability
    from any taint source is the same question asked in a way the graph can
    answer.
    """
    if (finding.get("cwe_id") or "") not in FLOW_CWES:
        return _result(NOT_APPLICABLE, "not a flow-dependent CWE")
    if not (finding.get("declared_source") or "").strip():
        return _result(FAIL, "flow CWE with no declared source")
    if node is None or node_id is None:
        return _result(NOT_APPLICABLE, "function not present in the call graph")
    if node.get("is_entry_point") or node.get("is_taint_source"):
        return _result(PASS, "function is itself an HTTP entry point")
    if node_id in reachable:
        return _result(PASS, "reachable from a taint source in the call graph")
    return _result(FAIL, "no taint source in the call graph reaches this function")


def check_cwe_in_taxonomy(finding: dict, taxonomy: frozenset) -> dict:
    """G4 — the CWE is one the prompt actually offered.

    A CWE outside the list was not chosen from the taxonomy, it was recalled
    from training. That does not make it wrong, but it is unscoreable: the
    evaluation compares against ground truth labels drawn from the same list.
    """
    cwe = finding.get("cwe_id")
    if not cwe:
        return _result(FAIL, "finding reports a vulnerability with no CWE")
    if cwe not in taxonomy:
        return _result(FAIL, f"{cwe} is not in the {len(taxonomy)}-CWE taxonomy")
    return _result(PASS, f"{cwe} is in the taxonomy")


def check_named_tokens(finding: dict, sample: Optional[dict], node: Optional[dict],
                       graph: dict) -> dict:
    """G5 — identifiers quoted in the explanation appear in the code.

    Only backticked, identifier-shaped spans count, and a token matches if it
    appears in the function body or in the name of a direct callee. Prose in
    backticks and multi-word spans are ignored, because the check is for
    invented API names, not for writing style.
    """
    if sample is None:
        return _result(NOT_APPLICABLE, "function not found in the extraction record")
    tokens = {
        t for t in _BACKTICKED.findall(finding.get("explanation") or "")
        if _IDENTIFIER.match(t.strip())
    }
    if not tokens:
        return _result(NOT_APPLICABLE, "explanation quotes no code tokens")

    body = (sample.get("code") or "")
    callee_names = set()
    if node:
        for cid in node.get("callees") or []:
            callee_names.add((graph.get(cid) or {}).get("function_name") or cid.split("::")[-1])

    missing = []
    for token in sorted(tokens):
        base = token.strip().rstrip("()").split(".")[-1]
        if base in body or token.strip() in body or base in callee_names:
            continue
        missing.append(token.strip())
    if missing:
        return _result(FAIL, f"tokens not present in the function or its callees: {missing}")
    return _result(PASS, f"all {len(tokens)} quoted tokens found in code")


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────

def check_patch_validity(finding: dict, patch: Optional[dict]) -> dict:
    """G6 — the fix the finding proposes is a real, applicable change.

    A finding that describes a defect correctly and then emits a diff that will
    not apply is still ungrounded in one respect: the remediation half of the
    output is unusable, and that half is what a developer acts on. The validator
    applies the hunk to an in-memory copy and re-parses with tree-sitter, so a
    pass means the patch located its context and produced syntactically valid
    code — not that the fix is correct.

    Scored from the saved patch record rather than by generating anything, so
    this costs nothing on any run that has already been through `patch`.
    """
    if patch is None:
        return _result(NOT_APPLICABLE, "no patch record for this finding")
    if not (patch.get("unified_diff") or "").strip():
        return _result(NOT_APPLICABLE, "patch record carries no diff")
    if patch.get("patch_valid") is True:
        return _result(PASS, "patch applies in memory and re-parses")
    return _result(FAIL, f"patch does not apply: {patch.get('patch_error') or 'unknown'}")


CHECKS = ("location", "line_citations", "flow_source", "cwe_in_taxonomy",
          "named_tokens", "patch_validity")


def _norm(p: str) -> str:
    return str(p or "").replace("\\", "/").lower()


def _match_patch(index: dict, finding: dict, sample: Optional[dict]) -> Optional[dict]:
    """The patch record for this finding, disambiguated by line range if needed.

    Same problem as sample resolution: several functions can share a name in one
    file, so where more than one patch matches, the one whose span is the
    function's own is taken and anything still ambiguous returns None rather
    than a guess.
    """
    rows = index.get((_norm(finding.get("file_path")), finding.get("function_name"))) or []
    if len(rows) == 1:
        return rows[0]
    if not rows or sample is None:
        return None
    for row in rows:
        if row.get("start_line") == sample.get("start_line"):
            return row
    return None


def _node_id(finding: dict) -> str:
    return f"{finding.get('file_path')}::{finding.get('function_name')}"


def taint_reachable(graph: dict) -> frozenset:
    """Every node reachable from any taint source by following callee edges.

    Computed once per run rather than per finding: on juice-shop that is one
    traversal of 1306 nodes instead of one per flagged finding.
    """
    queue = [
        nid for nid, n in graph.items()
        if n.get("is_taint_source") or n.get("is_entry_point")
    ]
    seen = set(queue)
    while queue:
        current = queue.pop()
        for nxt in (graph.get(current) or {}).get("callees") or []:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return frozenset(seen)


def score_findings(analysis: dict, extraction: dict, call_graph: dict,
                   patches: Optional[dict] = None) -> dict:
    """Run every check over every flagged finding in a saved analysis run.

    `patches` is the saved `<run_id>_patches.json` if one exists. Without it the
    patch check reports not-applicable for every finding rather than failing
    them: a run that was never patched has not proposed a bad fix, it has
    proposed none.
    """
    graph = call_graph.get("graph", call_graph)
    taxonomy = taxonomy_cwes()
    reachable = taint_reachable(graph)

    samples = {}
    for s in extraction.get("results", extraction if isinstance(extraction, list) else []):
        samples[(_norm(s["file_path"]), s["function_name"], s["start_line"])] = s
    by_name = {}
    for (path, name, start), s in samples.items():
        by_name.setdefault((path, name), []).append(s)

    patch_index = {}
    for row in (patches or {}).get("patches", []):
        patch_index.setdefault((_norm(row.get("file_path")), row.get("function_name")), []).append(row)

    nodes_by_name = {}
    for nid, n in graph.items():
        nodes_by_name.setdefault((_norm(n.get("file_path")), n.get("function_name")), nid)

    rows = []
    for finding in analysis.get("findings", []):
        if not finding.get("vulnerability_found"):
            continue
        key = (_norm(finding.get("file_path")), finding.get("function_name"))
        candidates = by_name.get(key) or []
        sample = None
        if len(candidates) == 1:
            sample = candidates[0]
        elif candidates:
            # Several functions share a name in one file (four `set` setters in
            # one Juice Shop model). Pick the one whose span contains the
            # reported lines; if none does, that IS the location failure, so
            # leave it unresolved rather than guessing.
            lines = [n for n in (finding.get("affected_lines") or []) if isinstance(n, int)]
            for c in candidates:
                if lines and all(c["start_line"] <= n <= c["end_line"] for n in lines):
                    sample = c
                    break
        nid = nodes_by_name.get(key)
        node = graph.get(nid) if nid else None

        results = {
            "location": check_location(finding, sample),
            "line_citations": check_line_citations(finding, sample),
            "flow_source": check_flow_source(finding, nid, node, reachable),
            "cwe_in_taxonomy": check_cwe_in_taxonomy(finding, taxonomy),
            "named_tokens": check_named_tokens(finding, sample, node, graph),
            "patch_validity": check_patch_validity(finding, _match_patch(patch_index, finding, sample)),
        }
        failures = [name for name, r in results.items() if r["status"] == FAIL]
        rows.append({
            "function_name": finding.get("function_name"),
            "file_path": finding.get("file_path"),
            "cwe_id": finding.get("cwe_id"),
            "grounded": not failures,
            "failed_checks": failures,
            "checks": results,
        })

    per_check = {}
    for name in CHECKS:
        counts = {PASS: 0, FAIL: 0, NOT_APPLICABLE: 0}
        for row in rows:
            counts[row["checks"][name]["status"]] += 1
        applicable = counts[PASS] + counts[FAIL]
        per_check[name] = {
            **counts,
            "pass_rate": round(counts[PASS] / applicable, 4) if applicable else None,
        }

    grounded = sum(1 for r in rows if r["grounded"])
    return {
        "findings_scored": len(rows),
        "grounded": grounded,
        "ungrounded": len(rows) - grounded,
        "groundedness_rate": round(grounded / len(rows), 4) if rows else None,
        "per_check": per_check,
        "rows": rows,
    }


def cross_tabulate(groundedness: dict, evaluation: dict) -> dict:
    """Does failing a check predict being a false positive?

    The question that decides whether this layer is only a robustness argument
    or also a way to raise precision without labels. Joins on (file, function),
    so findings on rows the ground truth does not cover are reported separately
    rather than silently dropped.
    """
    outcomes = {}
    for inst in evaluation.get("instances", []):
        outcomes[(_norm(inst["file"]), inst["function_name"])] = inst["outcome"]

    table = {"grounded": {"TP": 0, "FP": 0}, "ungrounded": {"TP": 0, "FP": 0}}
    unmatched = 0
    for row in groundedness["rows"]:
        key = None
        for (path, name), outcome in outcomes.items():
            if name == row["function_name"] and _norm(row["file_path"]).endswith(path):
                key = outcome
                break
        if key not in ("TP", "FP"):
            unmatched += 1
            continue
        table["grounded" if row["grounded"] else "ungrounded"][key] += 1

    out = {"table": table, "findings_not_in_ground_truth": unmatched}
    for bucket, counts in table.items():
        total = counts["TP"] + counts["FP"]
        out[f"{bucket}_precision"] = round(counts["TP"] / total, 4) if total else None
    return out
