from collections.abc import Mapping
from urllib.parse import urlencode

from fastapi import Response
from fastapi.datastructures import URL
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask


class OauthJsonResponse[T: BaseModel](Response):
    media_type = "application/json"

    def __init__(
        self,
        content: T,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        media_type: str | None = None,
        background: BackgroundTask | None = None,
    ) -> None:
        super().__init__(content, status_code, headers, media_type, background)
        self.content = content

    def render(self, content: T) -> bytes:
        return content.model_dump_json(exclude_none=True).encode("utf-8")


class OauthRedirectResponse[T: BaseModel](RedirectResponse):
    def __init__(
        self,
        url: str | URL,
        params: T,
        status_code: int = 303,
        headers: Mapping[str, str] | None = None,
        background: BackgroundTask | None = None,
    ) -> None:
        super().__init__(
            f"{url}?{urlencode(params.model_dump(mode='json', exclude_none=True))}",
            status_code,
            headers,
            background,
        )

        self.params = params
