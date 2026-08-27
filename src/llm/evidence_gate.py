"""Evidence requirements for flow-dependent CWEs.

Why this exists
---------------
On the juice-shop baseline, every one of the eight CWE-117 predictions was a
false positive - 22% of all false positives, from a single reasoning failure.
The analyzer flagged interpolation into a logger call without ever asking
whether the value was attacker-reachable. The eight values were challenge keys,
config-file entries, NODE_ENV, and arguments passed by internal callers only.

The pattern generalises: an injection CWE describes untrusted data reaching a
dangerous sink, so it needs a *source* as well as a sink. The agent already has
`get_taint_path` and the prompt already suggests it ("use this when you suspect
an injection or flow-based vuln"), but suggestion is not enough - the model
reached for it rarely and flagged anyway.

So the prompt requires the source to be named, in a machine-checkable form, and
this module holds both the requirement text and the check, so the CWE list the
prompt talks about and the CWE list the checker enforces cannot drift apart.

Measure, do not suppress
------------------------
A finding that fails the gate is recorded as failing, not dropped. Suppressing
it would silently change recall as well as precision and make the effect of this
stage impossible to read; the point of the gate is first to find out how often
the model can substantiate its own flow claims.
"""
from __future__ import annotations

import re
from typing import Optional

# CWEs that describe untrusted data reaching a dangerous sink. Each one is
# meaningless without a source, which is exactly the check the model was
# skipping. Deliberately excludes the authorization and crypto classes
# (CWE-639/862/347/798/...): those are properties of the code in front of you,
# not of a data flow, and demanding a taint path for them would suppress the
# findings this tool is best at.
#
# Every entry must also appear in `taxonomy.CWE_TAXONOMY_PROMPT`: demanding a
# declared source for a class the prompt never offered scores the model against
# a rule it was not given. CWE-22, CWE-611 and CWE-918 sat here in exactly that
# state until 2026-08-27. `tests/test_taxonomy_consistency.py` now asserts the
# containment so the two files cannot drift apart again unnoticed.
FLOW_CWES = frozenset({
    "CWE-89",    # SQL/NoSQL injection
    "CWE-79",    # XSS
    "CWE-95",    # eval / code injection
    "CWE-117",   # log injection
    "CWE-22",    # path traversal
    "CWE-918",   # SSRF
    "CWE-611",   # XXE
    "CWE-601",   # open redirect — a user-controlled URL reaching a redirect sink
    "CWE-1427",  # prompt injection — user text reaching a model prompt
})

# The model is asked to emit a line of the form `SOURCE: <where it enters>`.
# Matching is deliberately loose about position, punctuation and case: this is a
# check on whether the model did the reasoning, not a format exam, and a stricter
# pattern would mostly measure formatting compliance. The word boundary is what
# stops "resource:" and "datasource:" from counting.
_SOURCE_RE = re.compile(r"\bSOURCE\s*[:\-]\s*(\S.*)", re.IGNORECASE)

# Verdicts recorded on a finding.
SATISFIED = "satisfied"
MISSING_SOURCE = "missing_source"
NOT_APPLICABLE = "not_applicable"


EVIDENCE_GATE_PROMPT = """\
EVIDENCE GATE — flow-dependent CWEs (89, 79, 95, 117, 22, 918, 611, 601, 1427)
These describe untrusted data reaching a dangerous sink. They require a SOURCE,
not just a sink. Before reporting one you MUST be able to name the source, and
it must be one of:
  (a) a parameter of THIS function, where this function is a route handler
      (see the ROUTE CONTEXT block), or
  (b) a request object read directly in this function — req.body, req.query,
      req.params, req.headers, req.cookies, req.files, or an equivalent, or
  (c) a path returned by get_taint_path(<this function>) that starts at an
      entry point — quote that path in your explanation.
If you cannot name the source, the value is NOT attacker-controlled. A config
value, an environment variable, a hardcoded literal, an internal constant, a
value read from a file the application ships, a database row written only by the
app itself, or an argument passed in by an internal caller is NOT a source.
Say so and return clean.

For these CWEs ONLY, your explanation MUST contain a line of exactly this form:
  SOURCE: <where the untrusted value enters, and how it reaches the sink>
An explanation for one of these CWEs without a SOURCE line is invalid.
This does not apply to authorization, crypto, or business-logic CWEs — those are
properties of the code itself and need no taint path.
"""


def normalize_cwe(cwe_id: Optional[str]) -> Optional[str]:
    if not cwe_id:
        return None
    return str(cwe_id).strip().upper()


def requires_source(cwe_id: Optional[str]) -> bool:
    return normalize_cwe(cwe_id) in FLOW_CWES


def declared_source(explanation: Optional[str]) -> Optional[str]:
    """The text of the SOURCE line, or None if there isn't one."""
    if not explanation:
        return None
    match = _SOURCE_RE.search(explanation)
    if not match:
        return None
    text = match.group(1).strip()
    return text or None


def evaluate(
    cwe_id: Optional[str],
    vulnerability_found: bool,
    explanation: Optional[str],
) -> str:
    """One of SATISFIED / MISSING_SOURCE / NOT_APPLICABLE.

    Only applies to findings that actually claim a vulnerability: a clean
    verdict has no flow to substantiate.
    """
    if not vulnerability_found or not requires_source(cwe_id):
        return NOT_APPLICABLE
    return SATISFIED if declared_source(explanation) else MISSING_SOURCE
