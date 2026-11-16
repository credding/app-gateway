from typing import Annotated

from fastapi import Depends, HTTPException
from itsdangerous import BadSignature
from joserfc import jwt
from joserfc.errors import JoseError
from pydantic import ValidationError

from app_gateway.common.clock import now, to_timestamp
from app_gateway.common.cookies import RequestCookie
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.console_app.routes.auth import session_cookie
from app_gateway.console_app.schema import ConsoleSession
from app_gateway.settings import Settings, get_settings


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="unauthorized")


def require_user_id(
    settings: Annotated[Settings, Depends(get_settings)],
    console_session: Annotated[RequestCookie[ConsoleSession], Depends(session_cookie)],
) -> str:
    time = now()

    try:
        session = console_session.get_cookie(time)
    except BadSignature, ValueError, ValidationError:
        raise _unauthorized() from None
    if session is None:
        raise _unauthorized()

    access_token = (
        session.token.get("access_token") if isinstance(session.token, dict) else None
    )
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
        token = jwt.decode(access_token, keyset, algorithms=["ES256"])
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
