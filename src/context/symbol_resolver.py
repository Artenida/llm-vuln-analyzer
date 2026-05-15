class SymbolResolver:
    def resolve(self, raw: str) -> str:
        if not raw:
            return raw

        raw = raw.strip()

        if raw.endswith("()"):
            raw = raw[:-2]

        if "." in raw:
            raw = raw.split(".")[-1]

        return raw