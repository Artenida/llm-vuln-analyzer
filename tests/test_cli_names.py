"""
Every CLI command references only names that exist.

This exists because of a specific failure: a bulk edit that added a
`--chunk-oversized` override to `analyze` matched the same two lines in `patch`
as well, and `patch` has no such parameter. Nothing caught it. The module still
imported, `--help` still rendered, the whole suite still passed — because no
test ever executes a command body, and the name is only looked up at runtime.
The first sign was a patch job dying with `NameError` two seconds after the
button was pressed.

An import-time check cannot find this and neither can a type-free unit test, so
the check is a scope analysis: for each command, every name it reads from the
enclosing module scope must actually be defined there. `symtable` does the
scoping properly — parameters, locals, closures, comprehensions and nested
functions included — which a hand-rolled AST walk gets wrong.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_cli_names.py -v
"""
import builtins
import symtable
import sys
from pathlib import Path

import pytest

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

CLI_PATH = Path(__file__).parent.parent / "src" / "cli.py"


def _module_names(table: symtable.SymbolTable) -> set[str]:
    """Everything defined at module level: imports, defs, classes, assignments."""
    return {s.get_name() for s in table.get_symbols() if s.is_assigned() or s.is_imported()}


def _undefined(table: symtable.SymbolTable, defined: set[str]) -> list[tuple[str, str]]:
    """(function, name) for every global read that resolves to nothing.

    A name is a problem only when the function *reads* it from module scope and
    the module does not define it. Names it assigns, receives as parameters, or
    closes over are all bound and resolved by symtable itself.
    """
    problems: list[tuple[str, str]] = []
    for symbol in table.get_symbols():
        name = symbol.get_name()
        if not symbol.is_global() or symbol.is_assigned():
            continue
        if name in defined or hasattr(builtins, name):
            continue
        problems.append((table.get_name(), name))
    for child in table.get_children():
        problems.extend(_undefined(child, defined))
    return problems


@pytest.fixture(scope="module")
def cli_source() -> str:
    return CLI_PATH.read_text(encoding="utf-8")


def test_no_cli_command_reads_a_name_that_does_not_exist(cli_source):
    top = symtable.symtable(cli_source, str(CLI_PATH), "exec")
    problems = _undefined(top, _module_names(top))
    assert not problems, "undefined names in src/cli.py: " + ", ".join(
        f"{fn}() reads '{name}'" for fn, name in problems
    )


def test_the_check_catches_the_bug_it_was_written_for(cli_source):
    """A guard that cannot fail is not a guard.

    Re-introduces the exact regression — the override block copied into a
    command that has no such parameter — and asserts the check reports it.
    """
    marker = "    config = load_config(config_path)\n"
    assert cli_source.count(marker) >= 2, "cli.py no longer has the shape this reproduces"

    # The last command that loads a config — whichever it is. The bug was never
    # about `patch` specifically; it was about an edit landing in a second
    # command that has no such parameter, and any of them will do to prove the
    # check sees it.
    head, sep, tail = cli_source.rpartition(marker)
    broken = head + marker + "    if chunk_oversized is not None:\n        pass\n" + tail

    top = symtable.symtable(broken, str(CLI_PATH), "exec")
    problems = _undefined(top, _module_names(top))
    assert "chunk_oversized" in {name for _, name in problems}, problems
