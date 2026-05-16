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
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".tsx": Language.JAVASCRIPT,
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".hpp": Language.CPP,
    ".cc": Language.CPP,
}