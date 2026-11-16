from http import HTTPStatus

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import PathLike, StaticFiles
from starlette.types import Scope

from app_gateway.settings import get_settings

_FALLBACK_EXCLUDED_PREFIXES = "api/"
_IMMUTABLE_PREFIX = "_app/immutable/"
_INDEX = "index.html"


class SPAStaticFiles(StaticFiles):
    """Serves the SvelteKit build, falling back to index.html for client routes."""

    def get_directories(
        self,
        directory: PathLike | None = None,
        packages: list[str | tuple[str, str]] | None = None,
    ) -> list[PathLike]:
        return [
            get_settings().console_app_web_dir,
            *super().get_directories(directory, packages),
        ]

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != HTTPStatus.NOT_FOUND or path.startswith(
                _FALLBACK_EXCLUDED_PREFIXES
            ):
                raise
            response = await super().get_response(_INDEX, scope)
            path = _INDEX

        if path.startswith(_IMMUTABLE_PREFIX):
            response.headers["cache-control"] = "public, max-age=31536000, immutable"
        elif path in {_INDEX, "."} or path.endswith("/"):
            response.headers["cache-control"] = "no-cache"
        return response
