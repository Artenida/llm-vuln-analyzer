"""
src/preprocessing/data_loader.py

Loads Java Juliet test-suite samples from disk.

TARGET_CWES controls which vulnerability types are included.
Each entry uses the raw folder-name format (no hyphen): "CWE78", "CWE89", etc.
The loader normalises these to "CWE-78", "CWE-89" in the CodeSample.

Adding a new CWE to the dataset = add one string to TARGET_CWES below.
"""

import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CodeSample:
    function_name: str
    source_code: str
    file_path: str
    cwe_id: str
    is_vulnerable: bool
    language: str = "java"


# ---------------------------------------------------------------------------
# CWE selection
# ---------------------------------------------------------------------------
# Grouped by category so it is easy to enable/disable whole families.
# Every entry here must match the folder-name prefix in the Juliet tree,
# e.g. "CWE89" matches folder CWE89_SQL_Injection/

TARGET_CWES: set[str] = {
    # --- Injection ---
    "CWE78",    # OS Command Injection
    "CWE89",    # SQL Injection
    "CWE90",    # LDAP Injection
    "CWE643",   # XPath Injection

    # --- XSS family ---
    "CWE80",    # Cross-Site Scripting (XSS)
    "CWE81",    # XSS — Error Message
    "CWE83",    # XSS — Attribute

    # --- Path traversal ---
    "CWE23",    # Relative Path Traversal
    "CWE36",    # Absolute Path Traversal

    # --- Numeric errors ---
    "CWE190",   # Integer Overflow
    "CWE191",   # Integer Underflow

    # --- Memory / pointer ---
    "CWE476",   # NULL Pointer Dereference

    # --- Sensitive data exposure ---
    "CWE256",   # Plaintext Storage of Password
    "CWE259",   # Hard-coded Password
    "CWE319",   # Cleartext Transmission of Sensitive Info

    # --- Redirect ---
    "CWE601",   # Open Redirect
}


# ---------------------------------------------------------------------------
# Method extractor
# ---------------------------------------------------------------------------

def extract_methods(source: str) -> dict[str, str]:
    """
    Extract bad() and good*() method bodies from a Juliet Java file.
    Returns { method_name -> full method source }.
    """
    methods: dict[str, str] = {}
    pattern = re.compile(
        r'(public\s+(?:void|String)\s+(bad|good\w*)\s*\([^)]*\)'
        r'\s*(?:throws\s+\w+\s*)?\{)',
        re.MULTILINE,
    )
    for match in pattern.finditer(source):
        method_name = match.group(2)
        start = match.start()
        brace_count = 0
        end = start
        for j, ch in enumerate(source[start:], start):
            if ch == "{":
                brace_count += 1
            elif ch == "}":
                brace_count -= 1
                if brace_count == 0:
                    end = j + 1
                    break
        methods[method_name] = source[start:end]
    return methods


# ---------------------------------------------------------------------------
# Single-file loader
# ---------------------------------------------------------------------------

def load_juliet_sample(file_path: str) -> list[CodeSample]:
    """
    Load all bad/good methods from a single Juliet Java file.
    Returns [] if the file's CWE is not in TARGET_CWES.
    """
    path = Path(file_path)
    name = path.stem

    match = re.match(r"(CWE\d+)", name)
    if not match:
        return []

    cwe_raw = match.group(1)
    if cwe_raw not in TARGET_CWES:
        return []

    cwe_id = cwe_raw.replace("CWE", "CWE-")
    source  = path.read_text(errors="ignore")
    methods = extract_methods(source)

    samples = []
    for method_name, method_code in methods.items():
        is_vulnerable = method_name == "bad"
        samples.append(CodeSample(
            function_name=f"{name}::{method_name}",
            source_code=method_code,
            file_path=str(path),
            cwe_id=cwe_id,
            is_vulnerable=is_vulnerable,
            language="java",
        ))
    return samples


# ---------------------------------------------------------------------------
# Folder loader
# ---------------------------------------------------------------------------

def load_juliet_folder(
    folder_path: str,
    limit: int | None = None,
    limit_per_cwe: int | None = None,
) -> list[CodeSample]:
    """
    Walk the Juliet folder tree and load samples for every CWE in TARGET_CWES.

    Args:
        folder_path:   root of the Juliet testcases folder
        limit:         hard cap on total samples returned (applied last)
        limit_per_cwe: cap on samples per CWE — keeps the dataset balanced
                       so one large CWE does not dominate the metrics.
                       Applied before the global limit.

    Returns:
        list of CodeSample, sorted by CWE then file path for reproducibility
    """
    # Collect all samples grouped by CWE
    by_cwe: dict[str, list[CodeSample]] = defaultdict(list)

    for root, _, files in os.walk(folder_path):
        for f in sorted(files):                 # sorted → reproducible order
            if f.endswith(".java"):
                for sample in load_juliet_sample(os.path.join(root, f)):
                    by_cwe[sample.cwe_id].append(sample)

    # Apply per-CWE cap
    samples: list[CodeSample] = []
    for cwe in sorted(by_cwe):
        group = by_cwe[cwe]
        if limit_per_cwe is not None:
            group = group[:limit_per_cwe]
        samples.extend(group)

    # Apply global cap
    if limit is not None:
        samples = samples[:limit]

    return samples


# ---------------------------------------------------------------------------
# Dataset summary (useful for logging before a run)
# ---------------------------------------------------------------------------

def dataset_summary(samples: list[CodeSample]) -> dict:
    """
    Return a breakdown of how many samples exist per CWE and language.
    Printed by cli.py before the analysis loop starts.
    """
    by_cwe: dict[str, int] = defaultdict(int)
    vulnerable = 0
    safe = 0

    for s in samples:
        by_cwe[s.cwe_id] += 1
        if s.is_vulnerable:
            vulnerable += 1
        else:
            safe += 1

    return {
        "total":      len(samples),
        "vulnerable": vulnerable,
        "safe":       safe,
        "by_cwe":     dict(sorted(by_cwe.items())),
    }