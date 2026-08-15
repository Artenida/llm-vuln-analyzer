"""Attribution of a finding to the function where the defect actually lives.

Why this exists
---------------
The prompts carry a deliberate anti-bleed rule - "do NOT flag a vulnerability
because a CALLEE has it" - and it works. Without it, one bad sink lights up every
caller. But on the juice-shop baseline it worked too well: the model saw the
defect, correctly decided it was not the target's, and dropped the observation
entirely.

    securityAnswer.ts::set - "any hardcoded key issue is in the hmac function
                              itself, not in this caller."
    user.ts::set           - "any weakness lies in the sanitizeLegacy callee,
                              not here."

Measured against the call graph, three bugs are counted twice against the tool
this way - once as a false positive at the sink, once as a false negative at the
caller:

    lib/insecurity.ts::hash           <-> models/user.ts::set @75-77   (unsalted MD5)
    lib/insecurity.ts::sanitizeLegacy <-> models/user.ts::set @47-54   (weak sanitizer)
    lib/insecurity.ts::decode         <-> lib/insecurity.ts::discountFromCoupon

The fix is not to relax the anti-bleed rule. It is to let a finding name its
counterpart, so one detection is scored as one detection.

Why the cap matters
-------------------
Under any scoring that credits `also_implicates`, "implicate everything" is a
strictly winning strategy, and the metric stops measuring anything. The list is
capped, hard, at parse time. That cap is load-bearing, not tidiness.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)

# The most functions one finding may implicate. A real "the defect is here, and
# these callers rely on it" claim is small; a long list is the model hedging.
MAX_IMPLICATED = 3

# "<file>::<function>" - the node_id form used across the call graph.
_NODE_ID_RE = re.compile(r"^\s*(?P<file>[^:]+(?::[^:]+)*?)::(?P<fn>[\w$<>.]+)\s*$")


ATTRIBUTION_PROMPT = """\
ATTRIBUTION — where a finding belongs
The rules above tell you not to flag the target for a defect that lives in a
callee. That is correct, but do not simply discard the observation: report it
once, against the function where the fix belongs.
  - Set "attributed_to" to the node_id of the function whose code is defective,
    whenever that is NOT the target function. Leave it null when the defect is
    in the target itself.
  - Set "also_implicates" to the node_ids that are unsafe as a consequence
    (at most 3 — a longer list will be truncated and is treated as hedging).
  - Node_id form is "<file>::<function>", e.g. "lib/insecurity.ts::hash".
  - You still set vulnerability_found on the TARGET only when the target's own
    use of the defect is unsafe. A function that merely mentions a weak helper
    in a comment is not vulnerable.
Example: the target hashes a password by calling a helper that uses unsalted MD5.
The weakness is the helper's; the decision to rely on it for passwords is the
target's. Report it once, with attributed_to = the helper and also_implicates =
[the target].
"""


def normalize_node_id(value: Optional[str]) -> Optional[str]:
    """Tidy a model-supplied node_id, or None if it is not usable.

    Accepts the "<file>::<function>" form and a bare function name (the model
    supplies one often enough that rejecting it would throw away real
    attributions). Anything else - prose, an empty string - is dropped rather
    than stored, so downstream code never has to guess what a field means.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip().strip("`\"'")
    if not text or text.lower() in {"null", "none", "n/a", "-"}:
        return None

    match = _NODE_ID_RE.match(text)
    if match:
        file_part = match.group("file").replace("\\", "/").strip()
        return f"{file_part}::{match.group('fn').strip()}"

    # A bare name, e.g. "hash". Usable: the evaluator resolves by name and file.
    if re.fullmatch(r"[\w$<>.]+", text):
        return text
    return None


def clean_implicated(
    values, attributed_to: Optional[str] = None, target: Optional[str] = None
) -> List[str]:
    """Normalise, de-duplicate and cap an `also_implicates` list."""
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return []

    out: List[str] = []
    for raw in values:
        node_id = normalize_node_id(raw)
        if not node_id or node_id in out:
            continue
        # Naming the same function as both the defect's home and a consequence
        # of it is noise; keep attributed_to as the single answer.
        if attributed_to and node_id == attributed_to:
            continue
        out.append(node_id)

    if len(out) > MAX_IMPLICATED:
        logger.debug(
            "Truncating also_implicates for %s: %d entries, cap is %d",
            target or "<unknown>", len(out), MAX_IMPLICATED,
        )
        out = out[:MAX_IMPLICATED]
    return out


def matches_row(node_id: str, file: str, function_name: str) -> bool:
    """Whether a model-supplied node_id points at a given ground-truth row.

    File comparison is suffix-based because the run records absolute paths while
    the ground truth records repo-relative ones, and the model writes whatever it
    saw. The function name must match exactly - a looser test would let one
    finding claim credit for any row in the file.
    """
    if not node_id:
        return False
    norm = node_id.replace("\\", "/")
    if "::" in norm:
        node_file, _, node_fn = norm.rpartition("::")
    else:
        node_file, node_fn = "", norm

    if node_fn.strip() != function_name:
        return False
    if not node_file:
        # A bare function name carries no file evidence. Accept it only as a
        # name match; the caller decides whether that is enough.
        return True

    gt_file = (file or "").replace("\\", "/").lower().lstrip("/")
    node_file = node_file.lower().lstrip("/")
    return node_file.endswith(gt_file) or gt_file.endswith(node_file)
