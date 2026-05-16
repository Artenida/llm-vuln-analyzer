import json

from src.context.edge_cache import EdgeCache
from src.llm.openai_client import OpenAIResolver


class LLMEdgeResolver:
    def __init__(self, api_key: str):
        self.client = OpenAIResolver(api_key)
        self.cache = EdgeCache()

    def resolve(
        self,
        caller: str,
        raw_call: str,
        caller_code: str,
        candidates: list,
    ):
        if len(candidates) == 1:
            return {
                'target': candidates[0],
                'confidence': 1.0,
                'resolved_by': 'static',
            }

        cache_key = json.dumps({
            'caller': caller,
            'raw_call': raw_call,
            'candidates': candidates,
        }, sort_keys=True)

        cached = self.cache.get(cache_key)

        if cached:
            return cached

        payload = {
            'caller': caller,
            'raw_call': raw_call,
            'caller_code': caller_code,
            'candidates': candidates,
        }

        result = self.client.resolve_edge(payload)

        self.cache.set(cache_key, result)

        return result