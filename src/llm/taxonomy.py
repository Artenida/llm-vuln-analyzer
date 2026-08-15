"""The CWE taxonomy and severity rules the analyzer works to.

Why this is one module
----------------------
This text used to exist twice - once in `_REACT_SYSTEM` and once, hand-copied,
inside `_build_context_prompt`. The copies had already drifted: the ReAct prompt
listed 18 CWEs, the single-pass prompt 7. So the two analysis modes were being
compared on the claim that they differed only in whether the model could call
tools, when in fact one of them could not name most of the vulnerability classes
the other could. Any measured difference between the modes was partly an artefact
of that.

What Stage 4 added, and why
---------------------------
Eight of the fifteen misses on the juice-shop baseline are rows the ground truth
itself tags `taxonomy_scope: out_of_scope` - real, documented vulnerabilities the
tool had no label for. Two of those are worth quoting, because the model saw the
defect and had nowhere to put it:

    generateCoupon (CWE-345)
      "The function constructs a coupon code ... and applies a reversible
       encoding. There is no use of hardcoded secrets, injection, authorization
       bypass, or other security-relevant issues in this code alone."

    updateAuthenticatedUsers (CWE-347)
      "The function uses jwt.verify with the known public key and only stores
       tokens when verification succeeds; it does not accept unsigned or
       tampered tokens."

The first described the vulnerability precisely and returned clean because
CWE-345 was not in the list. The second is worse: the code calls `jwt.verify`
without an `algorithms` option, so a forged `alg:none` token passes - and the old
rule text ("jwt.decode vs jwt.verify") taught exactly the wrong test. The model
applied the rule correctly and got the wrong answer.

Every added class is a new way to be wrong, so each carries narrowing text. The
`ADDED_IN_STAGE_4` set exists so a re-run can be checked for new false positives
by class and an individual addition rolled back if it does not pay for itself.
"""
from __future__ import annotations

# Classes added in Stage 4. Kept as data so a re-run's new false positives can be
# attributed per class - each of these is a hypothesis, not a certainty.
ADDED_IN_STAGE_4 = frozenset({"CWE-345", "CWE-425", "CWE-776", "CWE-916", "CWE-200"})


CWE_TAXONOMY_PROMPT = """\
CWE assignment rules — use the MOST SPECIFIC applicable CWE:
  CWE-89    SQL/NoSQL built by string concat or template literal interpolation
  CWE-347   A token is trusted without its signature being properly verified.
            Calling a verify() function is NOT sufficient. It is still CWE-347 if:
              - no algorithm allowlist is pinned (no `algorithms: ['RS256']` or
                equivalent), so a forged `alg:none` token, or an HS256 token
                signed with the public key, would be accepted;
              - the library version predates the algorithm-confusion fix (check
                package.json if you can reach it);
              - the result of a decode-without-verify is used for ANY security
                decision — identity, ownership, role — even if a verify happens
                somewhere else.
            Reading a token purely for display or logging is not CWE-347.
  CWE-345   An integrity/authenticity token built with a REVERSIBLE, UNKEYED
            encoding (base64, z85, hex, Hashids, a bare checksum) instead of a
            MAC or signature. If an attacker who can read the algorithm can mint
            a valid token, it is CWE-345 — however obscure the encoding is.
            Not CWE-345 if the value carries a keyed MAC/signature, or if it is
            an opaque random identifier looked up server-side.
  CWE-798   Hardcoded credentials, secrets, API keys, or static bypass codes
  CWE-20    Security decision based on a client-supplied header (e.g. X-Forwarded-For for IP)
  CWE-306   Security step skipped (e.g. current-password not verified before change)
  CWE-208   Non-constant-time comparison of secrets (timing attack)
  CWE-269   Role or privilege accepted directly from user-controlled input
  CWE-639   Object/resource fetched or mutated by a client-supplied id with no check that
            it belongs to the requesting user (IDOR / broken object-level authorization)
  CWE-862   A privileged or sensitive action (refund, delete, role change, admin-only op)
            performed with no check of the caller's role/permission at all
  CWE-425   A sensitive file or endpoint reachable by URL alone with no authorization
            check, relying on the path not being guessed (forced browsing).
            Not CWE-425 if the resource is genuinely public (a homepage, a logo).
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
  CWE-776   User-supplied XML or YAML parsed with entity/anchor expansion enabled and no
            size or expansion limit (billion laughs / exponential entity expansion).
            A timeout alone does NOT fix it — the memory is allocated before the
            timeout fires. Not CWE-776 if expansion is disabled or capped.
  CWE-1333  A regular expression with nested or overlapping quantifiers (e.g. `(a+)+`,
            `([0-9]+)+`) applied to user-controlled input — catastrophic backtracking (ReDoS)
  CWE-117   User-controlled input written to a log sink (console.log, a logger call) without
            sanitizing newlines/control characters first — log injection / CRLF forging
  CWE-521   A password/credential policy (regex or length/complexity check) that imposes
            insufficient requirements (e.g. any length, no character-class requirement)
  CWE-916   A password, security answer, or other GUESSABLE secret stored or compared
            under a FAST hash (MD5, SHA-1, SHA-256, HMAC-SHA256) instead of a
            deliberately slow KDF (bcrypt/scrypt/argon2), or without a per-record salt.
            Only for secrets an attacker could brute-force offline. Hashing a file,
            a cache key, a random high-entropy token, or an ETag is NOT CWE-916.
  CWE-256   A password or credential stored or compared in plaintext instead of a salted
            hash, or logged/returned in plaintext
  CWE-200   A response returns data the caller should not see — another user's record,
            internal configuration, a CAPTCHA's own answer, or unauthenticated metrics
            and diagnostics. Not CWE-200 for data the application is meant to publish,
            or for fields the code explicitly masks or deletes before responding.
  NOTE: CWE-290 is for relay/reflection spoofing attacks — do NOT use it for static bypass codes
        or hardcoded admin secrets; use CWE-798 instead.
"""


SEVERITY_RULES_PROMPT = """\
Severity rules — apply consistently for the same CWE:
  high     CWE-89, CWE-347, CWE-345, CWE-798, CWE-639, CWE-862, CWE-95, CWE-256,
           CWE-916
  medium   CWE-20, CWE-208, CWE-269, CWE-306, CWE-841, CWE-915, CWE-362, CWE-79,
           CWE-1333, CWE-117, CWE-521, CWE-425, CWE-776, CWE-200
  low      Informational / defence-in-depth only
  Deviate from these defaults ONLY when you can state a concrete amplifying or
  mitigating factor (e.g. "no authentication required to reach this endpoint",
  or "this stores the credential itself, not just a one-time comparison of it").
"""


# Three baseline misses share one reasoning failure: the model excused a live
# code path because a flag guarded it.
#   product.ts::set - "the raw input path is only active in challenge mode and
#                      not exposed in production"
#   saveLoginIp     - "the special challenge branch bypass is intentional for
#                      testing"
# On a deliberately vulnerable application this is precisely backwards, and the
# reasoning would be wrong on a real one too: a feature flag is configuration,
# not a security control.
FEATURE_FLAG_RULE = """\
- A code path guarded by a feature flag, challenge flag, environment check, or
  "is this enabled" condition is still a code path. Report it and name the flag
  that enables it in your explanation. Do NOT assume a flag is off in
  production, and do NOT treat "this looks deliberate", "this is for testing",
  or "this is a challenge" as a reason to return clean — a deliberately planted
  vulnerability is still a vulnerability.
"""
