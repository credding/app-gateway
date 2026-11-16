from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App
from fastapi import Response
from fastapi.responses import PlainTextResponse

from app_gateway.common.validation import FormParams, parse_form_params_str
from app_gateway.settings import get_settings

_METADATA_PATH = "/.well-known/oauth-authorization-server"


@lru_cache
def get_oauth_client() -> StarletteOAuth2App:
    settings = get_settings()
    oauth = OAuth()
    client = oauth.register(
        name="app_gateway",
        server_metadata_url=settings.auth_server_issuer.rstrip("/") + _METADATA_PATH,
        client_id=settings.console_app_client_id,
        client_secret=settings.console_app_client_secret.get_secret_value(),
        client_kwargs={
            "token_endpoint_auth_method": "client_secret_post",
            "code_challenge_method": "S256",
            "scope": "openid profile",
        },
    )
    assert isinstance(client, StarletteOAuth2App)
    return client


def login_error_response(error: str, status_code: int = 400) -> Response:
    return PlainTextResponse(
        f"login failed: {error}",
        status_code=status_code,
        headers={"cache-control": "no-store"},
    )


def check_issuer(
    metadata: Mapping[str, Any],
    params: FormParams,
    issuer: str,
) -> Response | None:
    # RFC 8414 Section 3.3: the metadata must be for the issuer we configured.
    if metadata.get("issuer") != issuer:
        return login_error_response("issuer_mismatch", status_code=502)

    # RFC 9207: the authorization response must come from that same issuer.
    maybe_iss = parse_form_params_str(params, "iss")
    if maybe_iss is not None and maybe_iss != issuer:
        return login_error_response("invalid_request")

    return None
