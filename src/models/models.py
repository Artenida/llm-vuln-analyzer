from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    # TypeScript needs its own grammar, not the JavaScript one. The JS grammar
    # does not merely "lose the type annotations" on a .ts file — on some
    # constructs (a destructured *and* annotated parameter, e.g.
    # `({ query, headers }: Request, res: Response) => {}`) its error recovery
    # fails for the whole file and it returns ZERO functions, silently. Those
    # files then never reach analysis and never appear in ground truth, while
    # coverage still reports 100% of what was extracted.
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


EXTENSION_MAP = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".tsx": Language.TSX,
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".hpp": Language.CPP,
    ".cc": Language.CPP,
}