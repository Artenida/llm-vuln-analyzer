import re
from typing import List

from src.models.code_sample import ImportReference


REQUIRE_PATTERN = re.compile(
    r'const\s+(\w+)\s*=\s*require\(["\'](.+?)["\']\)'
)

IMPORT_PATTERN = re.compile(
    r'import\s+(\w+)\s+from\s+["\'](.+?)["\']'
)


class ImportExtractor:
    def extract(self, content: str) -> List[ImportReference]:
        imports = []

        for match in REQUIRE_PATTERN.finditer(content):
            alias, source = match.groups()
            imports.append(
                ImportReference(
                    alias=alias,
                    source=source,
                )
            )

        for match in IMPORT_PATTERN.finditer(content):
            alias, source = match.groups()
            imports.append(
                ImportReference(
                    alias=alias,
                    source=source,
                )
            )

        return imports