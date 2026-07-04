"""
OpenAI resolver for call graph edge resolution.
Always returns a dict with a "target" key.
"""
from __future__ import annotations

import json
import logging

from openai import OpenAI

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a call graph edge resolver for static analysis.

Given a function call site inside a caller function, determine which callee \
function from the candidate list is most likely being called.

You MUST respond with ONLY a valid JSON object matching this EXACT schema — \
no markdown, no prose, no extra keys:

{
  "target": string,
  "confidence": float between 0.0 and 1.0,
  "reasoning": string
}

Rules:
- "target" MUST be one of the strings from the "candidates" array, or null if \
none match.
- If the raw_call is an external library call (e.g. res.json, jwt.sign, \
console.log, fs.appendFileSync), set "target" to null.
- If the raw_call contains a dot (member expression like "authService.registerUser"), \
match on the method name part (e.g. "registerUser").
- Prefer exact name matches over partial matches.
- "confidence" must be between 0.0 and 1.0.
- "reasoning" is a single short sentence explaining your choice.
"""

USER_PROMPT_TEMPLATE = """\
Caller function: {caller}

Raw call expression found in the caller's source code: {raw_call}

Caller source code:
```
{caller_code}
```

Candidate internal functions (choose one or null):
{candidates}

Which candidate is being called by "{raw_call}"?
"""


class OpenAIResolver:

    def __init__(self, api_key: str, model: str = "o4-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def resolve_edge(self, payload: dict) -> dict:
        """
        Resolves a call graph edge.

        payload keys:
            caller      - node_id of the calling function
            raw_call    - the raw call expression string
            caller_code - source code of the caller
            candidates  - list of candidate function names

        Returns dict with keys: target, confidence, reasoning
        Always returns a dict — never raises on parse failure.
        """
        caller = payload.get("caller", "")
        raw_call = payload.get("raw_call", "")
        caller_code = payload.get("caller_code", "")
        candidates = payload.get("candidates", [])

        user_message = USER_PROMPT_TEMPLATE.format(
            caller=caller,
            raw_call=raw_call,
            caller_code=caller_code[:1500],  # cap to avoid token overflow
            candidates=json.dumps(candidates, indent=2),
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                #temperature=0,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
            )

            raw = response.choices[0].message.content or ""
            raw = raw.strip()

            # strip markdown fences if model wraps anyway
            if raw.startswith("```"):
                raw = "\n".join(
                    line for line in raw.splitlines()
                    if not line.startswith("```")
                ).strip()

            result = json.loads(raw)

            # normalise — guarantee "target" key exists
            if "target" not in result:
                # try to salvage common mismatches from old cache entries
                for alt_key in (
                    "resolved_callee", "callee", "resolved_call",
                    "resolved_to", "call",
                ):
                    if alt_key in result:
                        val = result[alt_key]
                        # only accept if it's actually in candidates
                        if isinstance(val, str) and val in candidates:
                            result["target"] = val
                            break
                else:
                    result["target"] = None

            # if target is not in candidates, treat as external
            if result.get("target") not in candidates:
                result["target"] = None

            return result

        except (json.JSONDecodeError, Exception) as e:
            logger.debug("OpenAI edge resolution failed for %r: %s", raw_call, e)
            return {"target": None, "confidence": 0.0, "reasoning": f"error: {e}"}