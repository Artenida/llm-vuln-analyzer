"""
Results persistence package.
Public API re-exported from submodules.
"""
from src.results.run_saver import save_run, save_extraction_results, save_call_graph, save_patches, make_run_id
from src.results.patch_generator import PatchGenerator, PatchResult
from src.results.patch_validator import PatchValidator, PatchValidationResult
from src.results.checkpoint import (
    CHECKPOINT_FILENAME, CheckpointHeader, CheckpointMismatch, RunCheckpoint,
)

__all__ = [
    "save_run",
    "save_extraction_results",
    "save_call_graph",
    "save_patches",
    "make_run_id",
    "PatchGenerator",
    "PatchResult",
    "PatchValidator",
    "PatchValidationResult",
    "RunCheckpoint",
    "CheckpointHeader",
    "CheckpointMismatch",
    "CHECKPOINT_FILENAME",
]
