from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional
from src.models.models import Language


@dataclass
class ImportReference:
    alias: str
    source: str
    imported_name: Optional[str] = None


@dataclass
class CallSite:
    raw_call: str
    line: int
    column: int
    candidate_targets: List[str] = field(default_factory=list)


@dataclass
class RouteDefinition:
    method: str
    path: str
    handlers: List[str]


@dataclass
class CodeSample:
    function_name: str
    file_path: str
    code: str                            # was "content" in the old flat models.py
    language: Language
    start_line: int
    end_line: int
    imports: List[ImportReference] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    call_sites: List[CallSite] = field(default_factory=list)
    routes: List[RouteDefinition] = field(default_factory=list)
    class_name: Optional[str] = None
    is_async: bool = False
    ast_node: Optional[Any] = None       # populated by TreeSitterParser
    raw_content: Optional[str] = None    # full file text, needed for call graph