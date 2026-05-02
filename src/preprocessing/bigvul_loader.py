"""
src/preprocessing/bigvul_loader.py

Loads the BigVul dataset from MSR_data_cleaned.csv.

Key columns used:
    func_before  — function source code BEFORE the fix (the vulnerable version)
    vul          — 1 = vulnerable, 0 = safe
    CWE ID       — e.g. "CWE-264" (note: space in column name)
    lang         — e.g. "C", "C++"

BigVul caveat (worth noting in your thesis):
    Label accuracy is known to be around 25% because many commits from
    large projects (Chromium, Android) are unrelated to security fixes.
    This is a field-wide known issue, not a data loading problem.
"""

from __future__ import annotations

import csv
import sys

import pandas as pd
from collections import defaultdict
from pathlib import Path

from src.preprocessing.data_loader import CodeSample

# BigVul functions can be very large — raise the CSV field size limit so
# the Python CSV parser does not reject them (default cap is 131072 bytes)
# sys.maxsize overflows on Windows — use the largest safe C long value instead
csv.field_size_limit(2147483647)
 
# ---------------------------------------------------------------------------
# CWE filter
# ---------------------------------------------------------------------------

BIGVUL_TARGET_CWES: set[str] = {
    # Injection (overlap with Juliet)
    "CWE-78",   # OS Command Injection
    "CWE-89",   # SQL Injection
    "CWE-90",   # LDAP Injection

    # Memory / pointer (C-specific, not in Juliet Java)
    "CWE-119",  # Buffer Overflow (general)
    "CWE-120",  # Buffer Copy without Size Check
    "CWE-125",  # Out-of-bounds Read
    "CWE-190",  # Integer Overflow
    "CWE-476",  # NULL Pointer Dereference
    "CWE-787",  # Out-of-bounds Write

    # Path traversal
    "CWE-22",   # Path Traversal

    # Info disclosure
    "CWE-200",  # Information Exposure
    "CWE-319",  # Cleartext Transmission

    # Access control
    "CWE-264",  # Permissions / Privileges
    "CWE-284",  # Improper Access Control
}

# Only read these columns — the rest are unused and waste memory
NEEDED_COLS = ["func_before", "vul", "CWE ID", "lang", "CVE ID", "file_name", "project"]

# Chunk size for reading — keeps peak memory low regardless of file size
CHUNK_SIZE = 500


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_bigvul_csv(
    csv_path: str,
    limit_per_cwe: int | None = 20,
    limit: int | None = None,
    target_cwes: set[str] | None = None,
    languages: set[str] | None = None,
) -> list[CodeSample]:
    """
    Load BigVul samples from MSR_data_cleaned.csv using chunked reading
    so the full 253MB file is never loaded into memory at once.

    Args:
        csv_path:      path to MSR_data_cleaned.csv
        limit_per_cwe: cap per CWE for balanced sampling (None = no cap)
        limit:         hard cap on total samples (applied last)
        target_cwes:   CWE IDs to include; None = use BIGVUL_TARGET_CWES
        languages:     languages to include e.g. {"C", "C++"}; None = all

    Returns:
        list of CodeSample with language set to the actual source language
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"BigVul CSV not found: {csv_path}")

    cwes = target_cwes if target_cwes is not None else BIGVUL_TARGET_CWES

    # Accumulate rows per CWE as we stream through the file
    # { cwe_id -> {"vuln": [rows...], "safe": [rows...]} }
    by_cwe: dict[str, dict[str, list[dict]]] = defaultdict(
        lambda: {"vuln": [], "safe": []}
    )

    half = (limit_per_cwe // 2) if limit_per_cwe is not None else None

    reader = pd.read_csv(
        csv_path,
        usecols=NEEDED_COLS,
        chunksize=CHUNK_SIZE,
        on_bad_lines="skip",    # skip malformed rows instead of crashing
        engine="python",        # python engine handles embedded newlines better
    )

    for chunk in reader:
        # Normalise
        chunk["CWE ID"] = chunk["CWE ID"].astype(str).str.strip()
        chunk["lang"]   = chunk["lang"].astype(str).str.strip()

        # Filter CWE
        chunk = chunk[chunk["CWE ID"].isin(cwes)]

        # Filter language
        if languages is not None:
            chunk = chunk[chunk["lang"].isin(languages)]

        # Drop bad rows
        chunk = chunk.dropna(subset=["func_before", "CWE ID", "lang"])
        chunk = chunk[~chunk["CWE ID"].str.lower().isin(["nan", "none", ""])]

        for _, row in chunk.iterrows():
            cwe  = str(row["CWE ID"]).strip()
            slot = "vuln" if int(row["vul"]) == 1 else "safe"

            # If we already have enough for this slot, skip
            if half is not None and len(by_cwe[cwe][slot]) >= half:
                continue

            by_cwe[cwe][slot].append(row)

        # Early exit if all CWE slots are full
        if half is not None and _all_slots_full(by_cwe, cwes, half):
            break

    # Flatten into CodeSample list
    samples: list[CodeSample] = []
    for cwe in sorted(by_cwe):
        for slot in ("vuln", "safe"):
            for row in by_cwe[cwe][slot]:
                code = str(row["func_before"]).strip()
                if not code or code.lower() == "nan":
                    continue

                is_vuln  = (slot == "vuln")
                language = str(row["lang"]).strip().lower()
                project  = str(row.get("project", "unknown")).strip()
                cve_id   = str(row.get("CVE ID", "unknown")).strip()
                label    = "bad" if is_vuln else "good"

                samples.append(CodeSample(
                    function_name=f"{project}::{cve_id}::{label}",
                    source_code=code,
                    file_path=str(row.get("file_name", csv_path)),
                    cwe_id=cwe,
                    is_vulnerable=is_vuln,
                    language=language,
                ))

    if limit is not None:
        samples = samples[:limit]

    return samples


def _all_slots_full(
    by_cwe: dict,
    cwes: set[str],
    half: int,
) -> bool:
    """Return True when every CWE in the target set has enough vuln+safe rows."""
    return all(
        len(by_cwe[cwe]["vuln"]) >= half and len(by_cwe[cwe]["safe"]) >= half
        for cwe in cwes
        if cwe in by_cwe
    )