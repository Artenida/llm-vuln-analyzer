import json
from pathlib import Path


class EdgeCache:
    def __init__(self, cache_file='edge_cache.json'):
        self.cache_file = Path(cache_file)

        if self.cache_file.exists():
            self.cache = json.loads(
                self.cache_file.read_text()
            )
        else:
            self.cache = {}

    def get(self, key: str):
        return self.cache.get(key)

    def set(self, key: str, value: dict):
        self.cache[key] = value
        self.cache_file.write_text(
            json.dumps(self.cache, indent=2)
        )