import yaml
from dataclasses import dataclass
from pathlib import Path

@dataclass
class LLMConfig:
    provider: str
    model: str
    max_tokens: int
    temperature: float

@dataclass
class DatasetConfig:
    folder: str
    limit: int | None

@dataclass
class OutputConfig:
    folder: str
    save_raw_response: bool

@dataclass
class AppConfig:
    llm: LLMConfig
    dataset: DatasetConfig
    output: OutputConfig

def load_config(config_path: str = "experiments/configs/default.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    return AppConfig(
        llm=LLMConfig(**raw["llm"]),
        dataset=DatasetConfig(**raw["dataset"]),
        output=OutputConfig(**raw["output"]),
    )