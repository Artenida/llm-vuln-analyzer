"""
Core data models shared across the pipeline.
"""
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


EXTENSION_MAP = {
    ".py":   Language.PYTHON,
    ".js":   Language.JAVASCRIPT,
    ".mjs":  Language.JAVASCRIPT,
    ".ts":   Language.JAVASCRIPT,   # treat ts as js for now
    ".jsx":  Language.JAVASCRIPT,
    ".tsx":  Language.JAVASCRIPT,
    ".c":    Language.C,
    ".h":    Language.C,
    ".cpp":  Language.CPP,
    ".hpp":  Language.CPP,
    ".cc":   Language.CPP,
}


@dataclass
class CodeSample:
    """
    One extracted function, ready for analysis.
    label is -1 when unknown (real-world code), 1 when vulnerable, 0 when safe.
    """
    code: str
    language: Language
    source: str                           # "file", "snippet"

    function_name: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None

    # set after analysis
    label: int = -1                       # -1=unknown, 0=safe, 1=vulnerable