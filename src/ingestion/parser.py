"""
Tree-sitter parser wrapper.
"""
import logging
from dataclasses import dataclass
from typing import Optional

from tree_sitter import Language, Node, Parser, Tree

logger = logging.getLogger(__name__)


@dataclass
class FunctionNode:
    name: str
    body: str
    start_line: int
    end_line: int
    ast_node: Node


# ──────────────────────────────────────────────────────
# Grammar loading
# ──────────────────────────────────────────────────────

def _load_grammars() -> dict:
    grammars = {}

    try:
        import tree_sitter_python as tspython
        grammars["python"] = Language(tspython.language())
    except Exception as e:
        logger.warning("Python grammar unavailable: %s", e)

    try:
        import tree_sitter_javascript as tsjavascript
        grammars["javascript"] = Language(tsjavascript.language())
    except Exception as e:
        logger.warning("JavaScript grammar unavailable: %s", e)

    try:
        import tree_sitter_c as tsc
        grammars["c"] = Language(tsc.language())
    except Exception as e:
        logger.warning("C grammar unavailable: %s", e)

    try:
        import tree_sitter_cpp as tscpp
        grammars["cpp"] = Language(tscpp.language())
    except Exception as e:
        logger.warning("C++ grammar unavailable: %s", e)

    return grammars


_GRAMMARS = None


def _get_grammars():
    global _GRAMMARS

    if _GRAMMARS is None:
        _GRAMMARS = _load_grammars()

    return _GRAMMARS


FUNCTION_NODE_TYPES = {
    "python": {"function_definition", "async_function_definition"},
    "javascript": {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    },
    "c": {"function_definition"},
    "cpp": {"function_definition"},
}


CALL_NODE_TYPES = {
    "python": {"call"},
    "javascript": {"call_expression"},
    "c": {"call_expression"},
    "cpp": {"call_expression"},
}


def node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace"
    )


# ──────────────────────────────────────────────────────
# Function name extraction
# ──────────────────────────────────────────────────────

def _extract_name(node: Node, language: str,
                  source_bytes: bytes) -> str:

    if language == "python":
        for child in node.children:
            if child.type == "identifier":
                return node_text(child, source_bytes)

    elif language == "javascript":

        for child in node.children:
            if child.type == "identifier":
                return node_text(child, source_bytes)
        
        parent = node.parent

        if parent.type in {
            "call_expression",
            "arguments",
            "statement_block",
            "program",
        }:
            return "<anonymous>"
        
        if parent:

            for child in parent.children:
                if child.type == "identifier":
                    return node_text(child, source_bytes)

            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left:
                    return node_text(left, source_bytes)

            if parent.type == "pair":
                key = parent.child_by_field_name("key")
                if key:
                    return node_text(key, source_bytes)

        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                return node_text(name_node, source_bytes)

    elif language in ("c", "cpp"):

        def find_identifier(n: Node):

            if n.type == "identifier":
                return node_text(n, source_bytes)

            for child in n.children:
                result = find_identifier(child)

                if result:
                    return result

            return None

        for child in node.children:
            if "declarator" in child.type:
                name = find_identifier(child)

                if name:
                    return name

    return "<anonymous>"


# ──────────────────────────────────────────────────────
# Function walker
# ──────────────────────────────────────────────────────

def _walk_functions(node: Node,
                    language: str,
                    source_bytes: bytes,
                    results: list,
                    max_lines: int):

    target_types = FUNCTION_NODE_TYPES.get(language, set())

    if node.type in target_types:

        start = node.start_point[0] + 1
        end = node.end_point[0] + 1

        line_count = end - start + 1

        if line_count <= max_lines:

            results.append(
                FunctionNode(
                    name=_extract_name(node, language, source_bytes),
                    body=node_text(node, source_bytes),
                    start_line=start,
                    end_line=end,
                    ast_node=node,
                )
            )

        return

    for child in node.children:
        _walk_functions(
            child,
            language,
            source_bytes,
            results,
            max_lines,
        )


# ──────────────────────────────────────────────────────
# Public parser
# ──────────────────────────────────────────────────────

class TreeSitterParser:

    def __init__(self, max_function_lines: int = 200):
        self.max_function_lines = max_function_lines

    @property
    def supported_languages(self) -> list[str]:
        return list(_get_grammars().keys())

    def parse(self,
              content: str,
              language: str) -> Optional[Tree]:

        grammars = _get_grammars()

        grammar = grammars.get(language)

        if grammar is None:
            return None

        try:
            parser = Parser(grammar)

            tree = parser.parse(
                content.encode("utf-8")
            )

            return tree

        except Exception as e:
            logger.error("Parse error: %s", e)
            return None

    def extract_functions(self,
                          content: str,
                          language: str) -> list[FunctionNode]:

        tree = self.parse(content, language)

        if tree is None:
            return []

        source_bytes = content.encode("utf-8")

        results = []

        _walk_functions(
            tree.root_node,
            language,
            source_bytes,
            results,
            self.max_function_lines,
        )

        return results

    def extract_call_names(self, node: Node, language: str, source_bytes: bytes) -> list[str]:

        call_types = CALL_NODE_TYPES.get(language, set())
        results = []

        def walk(n: Node):

            if n.type in call_types:

                func = n.child_by_field_name("function")

                if func:

                    # ─────────────────────────────────────────────
                    # FIX 1: JavaScript member_expression support
                    # ─────────────────────────────────────────────
                    if func.type == "member_expression":

                        obj = func.child_by_field_name("object")
                        prop = func.child_by_field_name("property")

                        if obj and prop:
                            results.append(
                                f"{node_text(obj, source_bytes)}.{node_text(prop, source_bytes)}"
                            )

                    else:
                        results.append(node_text(func, source_bytes))

            for child in n.children:
                walk(child)

        walk(node)
        return results