from datetime import datetime

from fastapi import Response
from fastapi.responses import JSONResponse
from joserfc import jwk

from app_gateway.auth_server.grants.common import (
    AccessTokenClaims,
    decode_access_token,
)
from app_gateway.auth_server.grants.id_token import (
    OPENID_SCOPE,
    has_openid_scope,
    scope_claims,
)
from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.session import AuthorizationScope, Session

_NO_STORE = {"cache-control": "no-store"}


def parse_bearer_token(authorization: str | None) -> str | Response:
    if authorization is None:
        return _bearer_challenge(401)

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return _bearer_challenge(401)

    token = token.strip()
    if not token:
        return _bearer_challenge(400, error="invalid_request")

    return token


def check_userinfo_token(
    access_token: str,
    keyset: jwk.KeySet,
    issuer: str,
    time: datetime,
) -> AccessTokenClaims | Response:
    claims = decode_access_token(access_token, keyset, issuer, time)
    if claims is None:
        return invalid_token_response()

    if not has_openid_scope(AuthorizationScope(scope=claims.scope)):
        return _bearer_challenge(403, error="insufficient_scope", scope=OPENID_SCOPE)

    return claims


def create_userinfo_response(
    claims: AccessTokenClaims,
    maybe_session: Session | None,
    maybe_identity: UserIdentity | None,
) -> Response:
    if (
        maybe_session is None
        or maybe_session.revoked_at is not None
        or maybe_session.user_id != claims.sub
        or maybe_identity is None
    ):
        return invalid_token_response()

    return JSONResponse(
        {"sub": maybe_session.user_id}
        | scope_claims(
            maybe_session, AuthorizationScope(scope=claims.scope), maybe_identity
        ),
        headers=_NO_STORE,
    )


def invalid_token_response() -> Response:
    return _bearer_challenge(401, error="invalid_token")


def _bearer_challenge(
    status_code: int,
    error: str | None = None,
    scope: str | None = None,
) -> Response:
    params = [
        f'{name}="{value}"'
        for name, value in (("error", error), ("scope", scope))
        if value is not None
    ]
    challenge = " ".join(["Bearer", ", ".join(params)]) if params else "Bearer"
    return Response(
        status_code=status_code,
        headers={"www-authenticate": challenge} | _NO_STORE,
    )
