"""
Code extractor.
Accepts a file path, directory path, or inline snippet.
Returns a flat list of CodeSample objects ready for analysis.
"""
import logging
from pathlib import Path
from typing import Union

from src.models import EXTENSION_MAP, CodeSample, Language
from src.ingestion.parser import TreeSitterParser

logger = logging.getLogger(__name__)

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "vendor",
    "dist", "build", ".next", "coverage", ".venv", "venv",
}


def _detect_language(path: Path) -> Language:
    return EXTENSION_MAP.get(path.suffix.lower(), Language.UNKNOWN)


class CodeExtractor:
    """
    Extracts functions from files, folders, or inline code snippets.
    All methods return List[CodeSample].
    """

    def __init__(self, max_function_lines: int = 200):
        self.parser = TreeSitterParser(max_function_lines=max_function_lines)

    # ── public entry points ───────────────────────────────────────────────────

    def from_path(self, path: Union[str, Path]) -> list[CodeSample]:
        """
        Accepts a file or directory path.
        Returns all extracted functions as CodeSample objects.
        """
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Path does not exist: {p}")

        if p.is_file():
            return self._from_file(p)

        if p.is_dir():
            return self._from_directory(p)

        raise ValueError(f"Path is neither a file nor a directory: {p}")

    def from_snippet(self, code: str, language: Union[str, Language]) -> list[CodeSample]:
        """
        Parses an inline code string.
        language should be 'python', 'javascript', 'c', or 'cpp'.
        """
        if isinstance(language, str):
            try:
                language = Language(language)
            except ValueError:
                language = Language.UNKNOWN

        if language == Language.UNKNOWN:
            logger.warning("Unknown language for snippet — skipping extraction")
            return []

        return self._extract_samples(
            content=code,
            language=language,
            file_path="<snippet>",
        )

    # ── internals ────────────────────────────────────────────────────────────

    def _from_file(self, path: Path) -> list[CodeSample]:
        language = _detect_language(path)
        if language == Language.UNKNOWN:
            logger.debug("Skipping unknown file type: %s", path)
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.error("Could not read %s: %s", path, e)
            return []

        return self._extract_samples(
            content=content,
            language=language,
            file_path=str(path),
        )

    def _from_directory(self, root: Path) -> list[CodeSample]:
        samples: list[CodeSample] = []
        for path in sorted(root.rglob("*")):
            # skip unwanted directories
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path.is_file():
                samples.extend(self._from_file(path))
        return samples

    def _extract_samples(self, content: str, language: Language,
                         file_path: str) -> list[CodeSample]:
        lang_str = language.value
        functions = self.parser.extract_functions(content, lang_str)

        if not functions:
            logger.debug("No functions extracted from %s", file_path)

        samples = []
        for fn in functions:
            samples.append(CodeSample(
                code=fn.body,
                language=language,
                source="file" if file_path != "<snippet>" else "snippet",
                function_name=fn.name,
                file_path=file_path,
                start_line=fn.start_line,
                end_line=fn.end_line,
            ))

        return samples