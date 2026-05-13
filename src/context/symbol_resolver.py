"""
Very lightweight symbol resolution for Phase 2A.
"""

from tree_sitter import Node


class SymbolResolver:

    def resolve(self, raw_name: str) -> str:
        """
        First version:
        - strips spaces
        - strips call syntax
        - normalizes method calls

        Example:
            "db.execute" -> "execute"
            "foo()" -> "foo"
        """

        if not raw_name:
            return raw_name

        raw_name = raw_name.strip()

        if raw_name.endswith("()"):
            raw_name = raw_name[:-2]

        if "." in raw_name:
            raw_name = raw_name.split(".")[-1]

        return raw_name