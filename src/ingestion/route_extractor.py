import re
from typing import List

from src.models.code_sample import RouteDefinition


ROUTE_PATTERN = re.compile(
    r'router\.(get|post|put|delete)\((.+?)\)',
    re.DOTALL,
)


class RouteExtractor:
    def extract(self, content: str) -> List[RouteDefinition]:
        routes = []

        for match in ROUTE_PATTERN.finditer(content):
            method = match.group(1).upper()
            args = match.group(2)

            parts = [p.strip() for p in args.split(',')]

            if not parts:
                continue

            path = parts[0].replace('"', '').replace("'", '')
            handlers = parts[1:]

            routes.append(
                RouteDefinition(
                    method=method,
                    path=path,
                    handlers=handlers,
                )
            )

        return routes