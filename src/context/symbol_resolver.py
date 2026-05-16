from pathlib import Path
from typing import List

from src.models.code_sample import CodeSample


class SymbolResolver:
    def resolve_candidates(
        self,
        sample: CodeSample,
        raw_call: str,
        all_functions: List[CodeSample],
    ) -> List[str]:
        candidates = []

        if '.' not in raw_call:
            return candidates

        alias, method = raw_call.split('.', 1)

        matching_import = next(
            (
                i for i in sample.imports
                if i.alias == alias
            ),
            None,
        )

        if not matching_import:
            return candidates

        target_file = Path(matching_import.source).stem

        for fn in all_functions:
            if (
                target_file in fn.file_path
                and fn.function_name == method
            ):
                candidates.append(
                    f"{fn.file_path}::{fn.function_name}"
                )

        return candidates