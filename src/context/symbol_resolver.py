class SymbolResolver:
    def resolve(self, raw: str) -> str:
        if not raw:
            return raw

        raw = raw.strip()

        if raw.endswith("()"):
            raw = raw[:-2]

        # ❌ DO NOT strip module context anymore
        return raw