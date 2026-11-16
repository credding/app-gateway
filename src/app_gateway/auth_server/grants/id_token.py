import hashlib
from datetime import datetime, timedelta
from typing import Any

from joserfc import jwk, jwt

from app_gateway.common.base64 import base64urlencode
from app_gateway.common.clock import to_seconds, to_timestamp
from app_gateway.policy import Client, User
from app_gateway.session import AuthorizationScope, Session

OPENID_SCOPE = "openid"

# OIDC Core Section 5.4: claims released for each standard scope.
SCOPE_CLAIMS: dict[str, tuple[str, ...]] = {
    "profile": (
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


def compute_at_hash(access_token: str) -> str:
    # OIDC Core Section 3.1.3.6: left half of the hash matching the ES256 alg.
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64urlencode(digest[: len(digest) // 2]).decode("ascii")


def create_id_token(
    session: Session,
    client: Client,
    scope: AuthorizationScope,
    user: User,
    signing_key: jwk.Key,
    access_token: str,
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
        "at_hash": compute_at_hash(access_token),
    }
    if nonce is not None:
        claims["nonce"] = nonce

    for scope_value in (scope.scope or "").split():
        for name in SCOPE_CLAIMS.get(scope_value, ()):
            if name in user.claims:
                claims[name] = user.claims[name]

    return jwt.encode(header, claims, signing_key)
