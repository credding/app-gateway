from typing import Annotated

from fastapi import Depends, HTTPException, Request
from joserfc import jwt
from joserfc.errors import JoseError

from app_gateway.common.clock import now, to_timestamp
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.settings import Settings, get_settings


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="unauthorized")


def require_user_id(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    time = now()

    token = api_request.session.get("token")
    if token is None:
        raise _unauthorized()

    access_token = token.get("access_token") if isinstance(token, dict) else None
    if not isinstance(access_token, str):
        raise _unauthorized()

    keyset = get_token_signing_keyset(
        settings.token_signing_key_seed.get_secret_value(),
        time,
        settings.key_rotation_schedule,
    )
    registry = jwt.JWTClaimsRegistry(
        now=to_timestamp(time),
        iss={"essential": True, "value": settings.auth_server_issuer},
        aud={"essential": True, "value": settings.console_app_client_id},
        sub={"essential": True},
        exp={"essential": True},
    )

    try:
        token = jwt.decode(access_token, keyset)
        if token.header.get("typ") != "at+jwt":
            raise _unauthorized()
        registry.validate(token.claims)
    except JoseError:
        raise _unauthorized() from None

    sub = token.claims["sub"]
    if not isinstance(sub, str):
        raise _unauthorized()
    return sub


type UserId = Annotated[str, Depends(require_user_id)]
