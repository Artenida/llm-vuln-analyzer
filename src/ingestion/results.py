"""
Extraction result persistence.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from src.models import CodeSample


def save_extraction_results(
    samples: list[CodeSample],
    source_path: str,
    output_folder: str,
) -> Path:

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_dir = Path(output_folder)

    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"extraction_{ts}.json"

    file_stats = defaultdict(
        lambda: {"functions": 0}
    )

    results = []

    for sample in samples:

        file_name = (
            Path(sample.file_path).name
            if sample.file_path
            else "<snippet>"
        )

        file_stats[file_name]["functions"] += 1

        results.append({
            "file_path": sample.file_path,
            "function_name": sample.function_name,
            "start_line": sample.start_line,
            "end_line": sample.end_line,
            "language": sample.language.value,
            "code": sample.code,
        })

    payload = {
        "metadata": {
            "source_path": source_path,
            "generated_at": datetime.now().isoformat(),
        },

        "summary": {
            "functions_found": len(samples),
        },

        "file_stats": dict(file_stats),

        "results": results,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            payload,
            f,
            indent=2,
            ensure_ascii=False,
        )

    return out_path