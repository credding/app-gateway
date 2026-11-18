from datetime import datetime, timedelta
from typing import Annotated, Any

from authlib.integrations.starlette_client import OAuthError
from fastapi import Depends, HTTPException, Request
from joserfc import jwt
from joserfc.errors import JoseError
from pydantic import ValidationError

from app_gateway.common.clock import now, to_timestamp
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.console_app.oauth_client import get_oauth_client
from app_gateway.console_app.schema import SessionToken
from app_gateway.settings import Settings, get_settings

_SESSION_TOKEN_KEY = "token"

# Refresh this long before the access token expires, so API requests made
# right after a session check don't race the expiry.
REFRESH_WINDOW = timedelta(minutes=5)


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="unauthorized")


def get_session_token(api_request: Request) -> SessionToken | None:
    value = api_request.session.get(_SESSION_TOKEN_KEY)
    if value is None:
        return None
    try:
        return SessionToken.model_validate(value)
    except ValidationError:
        return None


def set_session_token(api_request: Request, token: dict[str, Any]) -> SessionToken:
    session_token = SessionToken.model_validate(token)
    api_request.session[_SESSION_TOKEN_KEY] = session_token.model_dump(
        exclude_none=True
    )
    return session_token


def clear_session_token(api_request: Request) -> None:
    api_request.session.pop(_SESSION_TOKEN_KEY, None)


def needs_refresh(token: SessionToken, time: datetime) -> bool:
    if token.refresh_token is None or token.expires_at is None:
        return False
    return token.expires_at <= to_timestamp(time + REFRESH_WINDOW)


def validate_access_token(access_token: str, settings: Settings, time: datetime) -> str:
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


def require_user_id(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    token = get_session_token(api_request)
    if token is None:
        raise _unauthorized()
    return validate_access_token(token.access_token, settings, now())


async def require_refreshed_user_id(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Like `require_user_id`, but refreshes the access token when it is close
    to expiring.

    Only the session endpoint uses this. The auth server rotates refresh tokens
    and revokes the session on replay, so refreshing from several concurrent
    requests would end the session.
    """
    token = get_session_token(api_request)
    if token is None:
        raise _unauthorized()

    if needs_refresh(token, now()):
        client = get_oauth_client()
        try:
            refreshed = await client.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=token.refresh_token,
            )
        except OAuthError:
            clear_session_token(api_request)
            raise _unauthorized() from None
        token = set_session_token(api_request, refreshed)

    return validate_access_token(token.access_token, settings, now())


type UserId = Annotated[str, Depends(require_user_id)]
type RefreshedUserId = Annotated[str, Depends(require_refreshed_user_id)]
