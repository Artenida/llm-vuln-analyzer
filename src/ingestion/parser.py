"""
Tree-sitter parser wrapper.
Loads grammars once, parses files, extracts function nodes.
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


# ── grammar loading ───────────────────────────────────────────────────────────

def _load_grammars() -> dict:
    """
    Lazy-load grammars. Only imports what is installed.
    Returns dict mapping language string → tree_sitter Language object.
    """
    grammars = {}
    try:
        import tree_sitter_python as tspython
        grammars["python"] = Language(tspython.language())
    except Exception as e:
        logger.warning("Python grammar not available: %s", e)

    try:
        import tree_sitter_javascript as tsjavascript
        grammars["javascript"] = Language(tsjavascript.language())
    except Exception as e:
        logger.warning("JavaScript grammar not available: %s", e)

    try:
        import tree_sitter_c as tsc
        grammars["c"] = Language(tsc.language())
    except Exception as e:
        logger.warning("C grammar not available: %s", e)

    try:
        import tree_sitter_cpp as tscpp
        grammars["cpp"] = Language(tscpp.language())
    except Exception as e:
        logger.warning("C++ grammar not available: %s", e)

    return grammars


_GRAMMARS: Optional[dict] = None


def _get_grammars() -> dict:
    global _GRAMMARS
    if _GRAMMARS is None:
        _GRAMMARS = _load_grammars()
    return _GRAMMARS


# ── node type maps ────────────────────────────────────────────────────────────

# Node types that represent a function in each language
FUNCTION_NODE_TYPES = {
    "python":     {"function_definition", "async_function_definition"},
    "javascript": {"function_declaration", "function_expression",
                   "arrow_function", "method_definition"},
    "c":          {"function_definition"},
    "cpp":        {"function_definition"},
}

# Child field or node type used to get the function name
NAME_NODE_TYPES = {
    "python":     "identifier",
    "javascript": "identifier",
    "c":          "function_declarator",
    "cpp":        "function_declarator",
}


# ── name extraction ───────────────────────────────────────────────────────────

def _extract_name(node: Node, language: str, source_bytes: bytes) -> str:
    """
    Best-effort extraction of a function name from a node.
    Returns '<anonymous>' if the name cannot be found.
    """

    def node_text(n: Node) -> str:
        return source_bytes[n.start_byte:n.end_byte].decode(
            "utf-8",
            errors="replace"
        )

    # ── Python ─────────────────────────────────────────────
    if language == "python":
        for child in node.children:
            if child.type == "identifier":
                return node_text(child)

    # ── JavaScript / TypeScript ────────────────────────────
    elif language == "javascript":

        # function foo() {}
        for child in node.children:
            if child.type == "identifier":
                return node_text(child)

        # const foo = () => {}
        parent = node.parent

        if parent is not None:

            # variable_declarator
            for child in parent.children:
                if child.type == "identifier":
                    return node_text(child)

            # assignment_expression
            # foo = () => {}
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left:
                    return node_text(left)

            # object pair:
            # login: () => {}
            if parent.type == "pair":
                key = parent.child_by_field_name("key")
                if key:
                    return node_text(key)

        # class methods
        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                return node_text(name_node)

    # ── C / C++ ────────────────────────────────────────────
    elif language in ("c", "cpp"):

        def find_identifier(n: Node) -> Optional[str]:
            if n.type == "identifier":
                return node_text(n)

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

# ── walker ────────────────────────────────────────────────────────────────────

def _walk_functions(node: Node, language: str,
                    source_bytes: bytes, results: list,
                    max_lines: int) -> None:
    """
    Recursively walks the AST and collects function nodes.
    """
    target_types = FUNCTION_NODE_TYPES.get(language, set())

    if node.type in target_types:
        start = node.start_point[0] + 1   # 1-based
        end   = node.end_point[0] + 1
        line_count = end - start + 1

        if line_count > max_lines:
            logger.debug(
                "Skipping function at line %d (%d lines, limit %d)",
                start, line_count, max_lines,
            )
        else:
            body = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            name = _extract_name(node, language, source_bytes)
            results.append(FunctionNode(
                name=name,
                body=body,
                start_line=start,
                end_line=end,
            ))
        # do not descend into nested functions – keep top-level only
        return

    for child in node.children:
        _walk_functions(child, language, source_bytes, results, max_lines)


# ── public API ────────────────────────────────────────────────────────────────

class TreeSitterParser:
    """
    Parses source files using tree-sitter and extracts function definitions.
    """

    def __init__(self, max_function_lines: int = 200):
        self.max_function_lines = max_function_lines

    def parse(self, content: str, language: str) -> Optional[Tree]:
        """
        Parses content and returns a tree-sitter Tree.
        Returns None if the language is unsupported or parsing fails.
        """
        grammars = _get_grammars()
        grammar = grammars.get(language)
        if grammar is None:
            logger.warning("No grammar loaded for language '%s'", language)
            return None

        try:
            parser = Parser(grammar)
            
            tree = parser.parse(
            content.encode("utf-8")
            )

            # Detect syntax problems in the parsed tree
            if tree.root_node.has_error:
                logger.warning(
                    "Tree-sitter detected syntax issues in '%s'",
                language
                )

            return tree
        
        except Exception as e:
            logger.error("Parse error for language '%s': %s", language, e)
            return None

    def extract_functions(self, content: str, language: str) -> list[FunctionNode]:
        """
        Parses content and returns a list of FunctionNode objects.
        Returns empty list on any error.
        """
        tree = self.parse(content, language)
        if tree is None:
            return []

        results: list[FunctionNode] = []
        source_bytes = content.encode("utf-8")
        _walk_functions(tree.root_node, language, source_bytes, results, self.max_function_lines)
        return results

    @property
    def supported_languages(self) -> list[str]:
        return list(_get_grammars().keys())