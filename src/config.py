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
    limit_per_cwe: int | None


@dataclass
class BigVulConfig:
    enabled: bool
    csv_path: str
    limit_per_cwe: int | None
    limit: int | None
    languages: list[str] | None     # e.g. ["C", "C++"] or null for all


@dataclass
class OutputConfig:
    folder: str
    save_raw_response: bool


@dataclass
class AppConfig:
    llm: LLMConfig
    dataset: DatasetConfig
    bigvul: BigVulConfig
    output: OutputConfig


def load_config(config_path: str = "experiments/configs/default.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    ds = raw["dataset"]
    bv = raw.get("bigvul", {})

    return AppConfig(
        llm=LLMConfig(**raw["llm"]),
        dataset=DatasetConfig(
            folder=ds["folder"],
            limit=ds.get("limit"),
            limit_per_cwe=ds.get("limit_per_cwe"),
        ),
        bigvul=BigVulConfig(
            enabled=bv.get("enabled", False),
            csv_path=bv.get("csv_path", "data/raw/bigvul/MSR_data_cleaned.csv"),
            limit_per_cwe=bv.get("limit_per_cwe", 20),
            limit=bv.get("limit"),
            languages=bv.get("languages"),
        ),
        output=OutputConfig(**raw["output"]),
    )