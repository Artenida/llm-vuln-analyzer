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

# The taxonomy repair, 2026-08-27. Stage 4 consolidated the two prompt copies but
# did not check the merged list against what the datasets actually label, and
# nothing since has. Eight classes were in the juice-shop answer key and in no
# prompt, so thirteen rows asked the model for a verdict in a vocabulary it had
# never been given:
#
#   CWE-22   x5   CWE-611  x2   CWE-601  x1   CWE-602  x1
#   CWE-918  x1   CWE-352  x1   CWE-807  x1   CWE-1427 x1
#
# Three of them - CWE-22, CWE-611, CWE-918 - were simultaneously listed in
# `evidence_gate.FLOW_CWES`, so the gate was demanding a declared source for
# classes the prompt did not offer. That is the same drift Stage 4 repaired,
# reappearing between two files instead of two prompt strings, which is why
# `tests/test_taxonomy_consistency.py` now asserts the invariant rather than
# leaving it to be noticed again.
#
# Measured effect before the repair, on runs/juice-shop-backend: 4 of the 17
# missed rows carry one of these classes, and 9 of the 38 true positives were
# found anyway with the model supplying a CWE from training rather than from the
# list. The recall ceiling this lifts is 0.764, and it is a ceiling, not a
# prediction - each added class is also a new way to be wrong.
#
# Written from the CWE definitions, not from the rows that exposed the gap. The
# narrowing clauses describe what the class is not, in the same shape as the
# Stage 4 additions; none of them names a file, a function or a challenge, so
# this is not tuning to the answer key.
ADDED_IN_TAXONOMY_REPAIR = frozenset({
    "CWE-22", "CWE-352", "CWE-601", "CWE-602", "CWE-611", "CWE-807", "CWE-918", "CWE-1427",
})


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
  CWE-22    A file path built from user-controlled input reaches a filesystem or archive
            operation, so the caller can escape the intended directory. The guard is
            insufficient if it blocks only some separators (rejecting '/' but not '\\'),
            strips traversal sequences once rather than repeatedly, or truncates the path
            AFTER the extension or allowlist check rather than before it. Includes archive
            entry paths joined onto an output directory (zip slip).
            Not CWE-22 if the path comes from a fixed allowlist, or if the user-controlled
            part is used only as a lookup key and never as a path component.
  CWE-611   User-supplied XML is parsed with external entity resolution or DTD loading
            enabled (XML_PARSE_NOENT, XML_PARSE_DTDLOAD, `noent: true`, an unset
            `resolveExternalEntities: false`), so an entity can read local files or reach
            internal hosts. Not CWE-611 if entity resolution is explicitly disabled, or if
            the XML is generated by the application itself. Entity *expansion* limits with
            resolution still enabled do not fix it — that is CWE-776, a different class.
  CWE-918   A URL, host or address taken from user-controlled input is fetched by the
            server with no restriction on scheme, host, or address range, so the caller
            can reach internal services or cloud metadata endpoints (SSRF).
            Not CWE-918 if the destination is fixed, or validated against an allowlist of
            hosts resolved AFTER any redirect is followed.
  CWE-601   A redirect target taken from user-controlled input is not properly constrained
            to the application's own origin. A substring or `includes()` test against an
            allowlist is NOT a constraint: an attacker-controlled URL that merely contains
            an allowed string passes it. Not CWE-601 if the target is compared by parsed
            origin, or is an application-relative path with no scheme or host.
  CWE-352   A state-changing request is authorised only by an ambient credential the
            browser attaches automatically (a session cookie, HTTP Basic auth) with no
            unguessable per-request token, no origin/referer check, and no requirement to
            re-supply a value the attacker cannot know.
            Not CWE-352 if the credential must be read and attached by client code (an
            Authorization header from script-readable storage), or if the request is
            read-only.
  CWE-602   A security decision is made from a value the client computed and supplied —
            a price, a discount, a total, an entitlement, a validity flag — rather than
            recomputed or looked up server-side from an authoritative record.
            Not CWE-602 if the value is re-derived on the server and the client's copy is
            used only for display or as a cache key.
  CWE-807   A security decision — rate limiting, IP allowlisting, geolocation, identity —
            is based on a value the client controls and can set freely, most often a
            request header (X-Forwarded-For, X-Real-IP, User-Agent, a custom header).
            More specific than CWE-20 for this case; prefer it when the untrusted value
            is the INPUT TO the security decision itself. Not CWE-807 if the value is
            taken from the trusted connection (a socket address) or from a proxy header
            that a trusted proxy is configured to overwrite.
  CWE-1427  User-controlled text is placed into a prompt sent to a language model, and a
            constraint the application depends on is stated only in prose in that prompt
            (a maximum discount, a role, a refusal rule) with nothing enforcing it on the
            result. The model's output is then used without validation.
            Not CWE-1427 if the constraint is re-checked in code after the model responds,
            or if the output is only displayed and never acted on.
  NOTE: CWE-290 is for relay/reflection spoofing attacks — do NOT use it for static bypass codes
        or hardcoded admin secrets; use CWE-798 instead.
"""


SEVERITY_RULES_PROMPT = """\
Severity rules — apply consistently for the same CWE:
  high     CWE-89, CWE-347, CWE-345, CWE-798, CWE-639, CWE-862, CWE-95, CWE-256,
           CWE-916, CWE-22, CWE-611, CWE-918
  medium   CWE-20, CWE-208, CWE-269, CWE-306, CWE-841, CWE-915, CWE-362, CWE-79,
           CWE-1333, CWE-117, CWE-521, CWE-425, CWE-776, CWE-200, CWE-601,
           CWE-352, CWE-602, CWE-807, CWE-1427, CWE-290
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
