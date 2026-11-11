from functools import lru_cache

import httpx2


@lru_cache
def get_client() -> httpx2.AsyncClient:
    return httpx2.AsyncClient(http2=True)
