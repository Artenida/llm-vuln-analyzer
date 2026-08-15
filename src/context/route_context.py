"""Rendering of a function's HTTP route context for a prompt.

Kept separate from both prompt builders so the ReAct loop and the single-pass
path show the model exactly the same thing — otherwise the two modes stop being
comparable, and a metric difference between them stops meaning anything about
the modes themselves.

The block deliberately renders even when there are no registrations. Omitting it
reads as "not an endpoint", and that silent ambiguity is what produced ten
false IDOR reports: with the route table missing, every handler looked like an
unreachable orphan with no guards, so the analyzer assumed there were none.
"""
from __future__ import annotations

from typing import List, Optional

_NO_ROUTES = (
    "No HTTP route registration was found for this function. It may be an "
    "internal function, or its registration may live in a file or function this "
    "run could not parse. Do NOT conclude from this block alone that the "
    "function is unreachable or that no middleware guards it."
)

_GUIDANCE = (
    "Middleware listed under `runs before this function` has ALREADY executed by "
    "the time this function sees the request — including anything it validates, "
    "rejects, or overwrites on the request object. Do not report a missing check "
    "that one of these guards performs. If you do not know what a guard does, "
    "call get_source on it before flagging; guard names can be misleading (an "
    "authentication check is not an ownership check)."
)


def format_route_block(
    registrations: List[dict],
    function_name: str,
    max_routes: int = 6,
) -> str:
    """The `=== ROUTE CONTEXT ===` section for one function."""
    lines = ["=== ROUTE CONTEXT ==="]

    if not registrations:
        lines.append(_NO_ROUTES)
        return "\n".join(lines)

    lines.append(f"'{function_name}' is registered as an HTTP handler at:")

    for reg in registrations[:max_routes]:
        where = _location(reg)
        lines.append(f"  {reg.get('method', '?')} {reg.get('path') or '/'}{where}")

        guards = reg.get("guards_before") or []
        if guards:
            lines.append("    runs before this function, in order:")
            for g in guards:
                lines.append(f"      - {g}")
        else:
            lines.append("    runs before this function: nothing — it is first in the chain")

        for pg in reg.get("prefix_guards") or []:
            handlers = ", ".join(pg.get("handlers") or [])
            lines.append(
                f"    also mounted on the path prefix '{pg.get('path')}'"
                f"{_location(pg)}: {handlers}"
            )

    remaining = len(registrations) - max_routes
    if remaining > 0:
        lines.append(f"  ... and {remaining} further registration(s) not shown")

    lines.append("")
    lines.append(_GUIDANCE)
    return "\n".join(lines)


def format_chunk_note(sample) -> str:
    """A `=== PART OF A LARGER FUNCTION ===` block, or "" for a normal sample.

    Rendered as its own block rather than prepended to the code, because adding
    even one header line to the body would shift every line number in the chunk —
    and affected_lines are clamped to the sample's own range when the run is
    saved.
    """
    if not getattr(sample, "chunk_of", None):
        return ""
    return (
        "=== PART OF A LARGER FUNCTION ===\n"
        f"This is part {sample.chunk_index} of {sample.chunk_total} of "
        f"'{sample.chunk_of}', which was too long to analyse in one piece.\n"
        "Statements outside this part are NOT shown. Anything set up earlier in "
        "the function — a guard registered before this point, a variable assigned "
        "above — is still in effect here.\n"
        "Report only what is wrong in the lines you can see, and do not report a "
        "missing setup step that an unseen part may perform."
    )


def _location(reg: dict) -> str:
    file_path = reg.get("source_file") or ""
    line: Optional[int] = reg.get("source_line")
    short = file_path.replace("\\", "/").split("/")[-1] if file_path else ""
    if short and line:
        return f"   ({short}:{line})"
    if short:
        return f"   ({short})"
    return ""
