import json
from urllib.parse import parse_qs, urlsplit

from fastapi import Response


def redirect_location(response: Response) -> tuple[str, dict[str, str]]:
    """Split a redirect response's location into its base URL and query params."""
    parts = urlsplit(response.headers["location"])
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    params = {key: values[0] for key, values in parse_qs(parts.query).items()}
    return base, params


def error_body(response: Response) -> dict[str, str]:
    """Decode an OAuth JSON error response body."""
    return json.loads(bytes(response.body))
