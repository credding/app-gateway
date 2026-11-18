from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.metadata import (
    create_authorization_server_metadata_response,
    create_jwks_response,
)
from app_gateway.common.clock import now
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.settings import Settings, get_settings

router = APIRouter()


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
async def oauth_authorization_server_metadata(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    return create_authorization_server_metadata_response(
        settings.auth_server_issuer,
        str(api_request.url_for("oauth_authorize")),
        str(api_request.url_for("oauth_token")),
        str(api_request.url_for("oauth_device_authorization")),
        str(api_request.url_for("oauth_certs")),
    )


@router.get("/oauth/certs")
async def oauth_certs(
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    return create_jwks_response(
        get_token_signing_keyset(
            settings.token_signing_key_seed.get_secret_value(),
            now(),
            settings.key_rotation_schedule,
        )
    )
