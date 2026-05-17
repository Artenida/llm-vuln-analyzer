"""
Configuration. Loads experiments/configs/default.yaml into typed dataclasses.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    max_tokens: int = 3000        # bumped from 2000 — longer prompts need more room
    temperature: float = 0.0


@dataclass
class IngestionConfig:
    max_function_lines: int = 200
    skip_dirs: list[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__",
        "vendor", "dist", "build",
    ])


@dataclass
class OutputConfig:
    results_folder: str = "experiments/results"
    extraction_folder: str = "experiments/results/extraction"
    context_folder: str = "experiments/results/context"
    analysis_folder: str = "experiments/results/analysis"
    evaluation_folder: str = "experiments/results/evaluation"
    save_per_run: bool = True


@dataclass
class AgentConfig:
    react_mode: bool = False     # use ReAct loop instead of single-pass
    max_steps: int = 5           # max tool calls per function in ReAct mode


@dataclass
class AppConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)

    @property
    def openai_api_key(self) -> Optional[str]:
        return os.environ.get("OPENAI_API_KEY")


def load_config(path: Optional[str] = None) -> AppConfig:
    if path is None:
        path = os.path.join(
            Path(__file__).parent.parent,
            "experiments", "configs", "default.yaml",
        )

    config_path = Path(path)
    if not config_path.exists():
        return AppConfig()

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    llm_raw = raw.get("llm", {})
    ing_raw = raw.get("ingestion", {})
    out_raw = raw.get("output", {})
    agt_raw = raw.get("agent", {})

    return AppConfig(
        llm=LLMConfig(
            provider=llm_raw.get("provider", "openai"),
            model=llm_raw.get("model", "gpt-4o-mini"),
            max_tokens=llm_raw.get("max_tokens", 3000),
            temperature=llm_raw.get("temperature", 0.0),
        ),
        ingestion=IngestionConfig(
            max_function_lines=ing_raw.get("max_function_lines", 200),
            skip_dirs=ing_raw.get("skip_dirs", [
                "node_modules", ".git", "__pycache__", "vendor", "dist", "build",
            ]),
        ),
        output=OutputConfig(
            results_folder=out_raw.get("results_folder", "experiments/results"),
            extraction_folder=out_raw.get("extraction_folder", "experiments/results/extraction"),
            context_folder=out_raw.get("context_folder", "experiments/results/context"),
            analysis_folder=out_raw.get("analysis_folder", "experiments/results/analysis"),
            evaluation_folder=out_raw.get("evaluation_folder", "experiments/results/evaluation"),
            save_per_run=out_raw.get("save_per_run", True),
        ),
        agent=AgentConfig(
            react_mode=agt_raw.get("react_mode", False),
            max_steps=agt_raw.get("max_steps", 5),
        ),
    )