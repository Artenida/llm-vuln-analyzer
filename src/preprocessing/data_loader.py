import os
import re
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

TARGET_CWES = {"CWE89", "CWE78", "CWE80"}

def extract_methods(source: str) -> dict[str, str]:
    """Extract bad() and good() method bodies from a Juliet Java file."""
    methods = {}
    # Match method definitions: public void bad() / good() / goodG2B() etc.
    pattern = re.compile(
        r'(public\s+(?:void|String)\s+(bad|good\w*)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{)',
        re.MULTILINE
    )
    matches = list(pattern.finditer(source))
    for i, match in enumerate(matches):
        method_name = match.group(2)
        start = match.start()
        # Find the end of this method by counting braces
        brace_count = 0
        end = start
        for j, ch in enumerate(source[start:], start):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = j + 1
                    break
        methods[method_name] = source[start:end]
    return methods

def load_juliet_sample(file_path: str) -> list[CodeSample]:
    path = Path(file_path)
    name = path.stem

    # Skip non-testcase files
    match = re.match(r"(CWE\d+)", name)
    if not match:
        return []
    cwe_raw = match.group(1)
    if cwe_raw not in TARGET_CWES:
        return []

    cwe_id = cwe_raw.replace("CWE", "CWE-")
    source = path.read_text(errors="ignore")
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

def load_juliet_folder(folder_path: str) -> list[CodeSample]:
    samples = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.endswith(".java"):
                samples.extend(load_juliet_sample(os.path.join(root, f)))
    return samples