import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from src.ingestion.parser import TreeSitterParser

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
PROJECT_PATH = Path(
    r"C:\Users\User\Desktop\app-test\auth-service"
)

SUPPORTED_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs",
}

parser = TreeSitterParser()

# -------------------------------------------------
# DATA CONTAINERS
# -------------------------------------------------
results = []
issues = []
file_stats = defaultdict(lambda: {"functions": 0})

total_files = 0
total_functions = 0

scan_start_time = datetime.utcnow()

# -------------------------------------------------
# SCAN PROJECT
# -------------------------------------------------
for file_path in PROJECT_PATH.rglob("*"):

    if file_path.suffix not in SUPPORTED_EXTENSIONS:
        continue

    total_files += 1

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except Exception as e:
        issues.append({
            "file": file_path.name,
            "message": f"Could not read file: {str(e)}"
        })
        continue

    functions = parser.extract_functions(
        content,
        "javascript"
    )

    print(f"\n[{file_path.name}] → {len(functions)} functions")

    # detect parser warnings
    if "syntax issues" in str(functions):
        issues.append({
            "file": file_path.name,
            "message": "Tree-sitter detected syntax issues in 'javascript'"
        })

    for fn in functions:
        total_functions += 1

        file_stats[file_path.name]["functions"] += 1

        print(
            f"  - {fn.name} ({fn.start_line}-{fn.end_line})"
        )

        results.append({
            "file_path": str(file_path),
            "function_name": fn.name,
            "start_line": fn.start_line,
            "end_line": fn.end_line,
            "body": fn.body,
            "language": "javascript",
        })

scan_end_time = datetime.utcnow()

# -------------------------------------------------
# METADATA
# -------------------------------------------------
metadata = {
    "project_path": str(PROJECT_PATH),
    "scanned_at": scan_start_time.isoformat() + "Z",
    "finished_at": scan_end_time.isoformat() + "Z",
    "duration_seconds": (scan_end_time - scan_start_time).total_seconds(),
    "supported_extensions": list(SUPPORTED_EXTENSIONS),
}

# -------------------------------------------------
# FINAL STRUCTURED OUTPUT
# -------------------------------------------------
output_data = {
    "metadata": metadata,

    "summary": {
        "files_scanned": total_files,
        "functions_found": total_functions,
        "issues": issues
    },

    "file_stats": dict(file_stats),

    "results": results
}

# -------------------------------------------------
# SAVE OUTPUT
# -------------------------------------------------
output_dir = Path(
    "experiments/results/extraction"
)

output_dir.mkdir(parents=True, exist_ok=True)

output_path = output_dir / "auth_service_extraction.json"

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(output_data, f, indent=2, ensure_ascii=False)

# -------------------------------------------------
# CONSOLE SUMMARY (UNCHANGED OUTPUT STYLE)
# -------------------------------------------------
print("\n" + "=" * 60)
print("EXTRACTION SUMMARY")
print("=" * 60)
print(f"Files scanned     : {total_files}")
print(f"Functions found   : {total_functions}")
print(f"JSON output       : {output_path.resolve()}")

if issues:
    print("\nISSUES:")
    for i in issues:
        print(f" - {i['file']}: {i['message']}")

print("=" * 60)