# Patch Generation & Validation (Sprint 3)

## Goal

Given a confirmed vulnerability finding, generate a concrete code fix and validate it — as a proposal the user reviews, never a change silently applied to their project.

## Pipeline

```
analysis.json (completed run)
        │
        ▼
  re-extract flagged functions' source (tree-sitter, from source_path)
        │
        ▼
  PatchGenerator.generate()  ── LLM call: (code, explanation, cwe_id) → unified diff
        │
        ▼
  PatchValidator.validate()  ── apply diff to an in-memory copy, re-parse with tree-sitter
        │
        ▼
  experiments/results/patches/<run_id>_patches.json   (always written)
        │
        ▼ (only if --apply is passed)
  confirmation prompt → validated patches written into the actual source files
```

## Components

- **`src/results/patch_generator.py` — `PatchGenerator`**
  Calls the LLM with the function's original code, its vulnerability explanation, and CWE id. Returns a `PatchResult(unified_diff, error)`. Never touches disk.

- **`src/results/patch_validator.py` — `PatchValidator`**
  Parses the unified diff into hunks and applies them to an in-memory copy of the function source only. Hunk context is located with an exact scan first, falling back to `difflib.SequenceMatcher` fuzzy matching to tolerate small line-number drift in LLM-generated diffs. The patched result is re-parsed with tree-sitter (`has_error` check) to confirm it's still syntactically valid. Returns `PatchValidationResult(valid, patched_code, error)`. **Never writes to the original file.**

- **`VulnerabilityReport`** (`src/llm/client.py`) gained `unified_diff: str`, `patch_valid: Optional[bool]`, `patch_error: Optional[str]` — populated by the `patch` command, not by `analyze`.

- **CLI `patch` command** (`src/cli.py`)
  Takes a completed run JSON (`--results`), re-extracts the flagged functions' source from `source_path` (or `--path` override), generates + validates a patch per finding, and saves everything to `experiments/results/patches/<run_id>_patches.json` by default — **the analyzed project is untouched**.

## The `--apply` flag (opt-in only)

`patch --apply` writes validated (`patch_valid: true`) patches into the actual source files, replacing each function's original line range (`start_line`–`end_line`) with `patched_code`. This is:

- **Never the default** — plain `patch` only ever produces the JSON artifact.
- **Gated behind explicit confirmation** — lists every file/function that will be overwritten and prompts (`y/N`) unless `--yes` is also passed for non-interactive use.
- **Best-effort** — if the source file has changed since the analysis run, the line-range replacement may be stale; the confirmation step is the safety net.

**Why:** this tool is meant for other people to run against their own codebases. A security analysis tool that silently edits the project it's scanning is a bad trust model — the user must stay in control of whether any suggested change is actually applied.

## `<run_id>_patches.json` schema

```json
{
  "schema_version": "1.0",
  "run_id": "analysis_o4_mini_20260704_120000",
  "source_path": "path/to/project",
  "summary": { "total_patches": 8, "valid": 6, "invalid": 2 },
  "patches": [
    {
      "function_name": "findByUsername",
      "file_path": "services/authService.js",
      "cwe_id": "CWE-89",
      "severity": "high",
      "start_line": 40,
      "end_line": 46,
      "unified_diff": "--- a/findByUsername\n+++ b/findByUsername\n...",
      "patch_valid": true,
      "patch_error": null,
      "patched_code": "function findByUsername(username) {\n  ...\n}"
    }
  ]
}
```

`patch_error` values: `empty_diff`, `hunk_context_not_found`, `syntax_error_after_patch`, `unsupported_language_or_parse_failure`, `empty_llm_response`, `api_error: ...`, `source_not_found`.

## Exit criteria (from `docs/sprint-plan.md`)

- [x] Running `patch` never modifies the analyzed project unless `--apply` is explicitly passed
- [x] Validated patches pass a tree-sitter syntax check (enforced by `PatchValidator`, covered by `tests/test_patching.py`)
- [ ] Patches apply cleanly to a majority of flagged functions in the reference dataset — not yet measured; run `patch` against a completed `auth-service` analysis run with a real API key to get thesis-quality numbers
