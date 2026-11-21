from datetime import datetime, timedelta
from typing import Any

from joserfc import jwk, jwt

from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.common.clock import to_seconds, to_timestamp
from app_gateway.policy import Client
from app_gateway.session import AuthorizationScope, Session

OPENID_SCOPE = "openid"
PROFILE_SCOPE = "profile"

SCOPE_CLAIMS: dict[str, tuple[str, ...]] = {
    PROFILE_SCOPE: (
        "name",
        "pronouns",
        "family_name",
        "given_name",
        "preferred_username",
        "picture",
    ),
    "email": ("email",),
}

ID_TOKEN_CLAIMS: tuple[str, ...] = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "at_hash",
)


def has_openid_scope(scope: AuthorizationScope) -> bool:
    return OPENID_SCOPE in (scope.scope or "").split()


def create_id_token(
    session: Session,
    client: Client,
    scope: AuthorizationScope,
    identity: UserIdentity,
    signing_key: jwk.Key,
    nonce: str | None,
    issuer: str,
    time: datetime,
    lifetime: timedelta,
) -> str:
    issued_at = to_timestamp(time)

    header: dict[str, Any] = {"alg": "ES256", "typ": "JWT", "kid": signing_key.kid}
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": session.user_id,
        "aud": client.client_id,
        "iat": issued_at,
        "exp": issued_at + to_seconds(lifetime),
        "auth_time": to_timestamp(session.issued_at),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    claims |= scope_claims(session, scope, identity)

    return jwt.encode(header, claims, signing_key)


def scope_claims(
    session: Session,
    scope: AuthorizationScope,
    identity: UserIdentity,
) -> dict[str, Any]:
    claims: dict[str, Any] = {}

    scope_values = (scope.scope or "").split()
    for scope_value in scope_values:
        for name in SCOPE_CLAIMS.get(scope_value, ()):
            if name in identity.user.claims:
                claims[name] = identity.user.claims[name]

    if PROFILE_SCOPE in scope_values:
        claims["idp_issuer"] = session.idp_issuer
        claims["idp_subject"] = identity.identity.idp_subject

    return claims
