import json

from openai import OpenAI


class OpenAIResolver:
    def __init__(self, api_key: str, model='gpt-4.1-mini'):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def resolve_edge(self, payload: dict):
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
                {
                    'role': 'system',
                    'content': (
                        'You resolve software call graph edges. '
                        'Return valid JSON only.'
                    )
                },
                {
                    'role': 'user',
                    'content': json.dumps(payload, indent=2)
                }
            ]
        )

        raw = response.choices[0].message.content or ""
        raw = raw.strip()
        if raw.startswith("```"):
            raw = "\n".join(l for l in raw.splitlines() if not l.startswith("```")).strip()
        return json.loads(raw)