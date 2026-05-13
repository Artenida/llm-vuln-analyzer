"""
Core data models shared across the pipeline.
"""
from dataclasses import dataclass, field
from typing import Optional, Any
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
    ".ts":   Language.JAVASCRIPT,
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
    """

    code: str
    language: Language
    source: str

    function_name: Optional[str] = None
    file_path: Optional[str] = None

    start_line: Optional[int] = None
    end_line: Optional[int] = None

    # NEW ───────────────────────────────────────────────
    ast_node: Optional[Any] = None
    raw_content: Optional[str] = None

    # analysis metadata
    label: int = -1