from datetime import timedelta

import pytest
from joserfc import jwk, jwt

from app_gateway.auth_server.grants.id_token import create_id_token, has_openid_scope
from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.common.clock import to_timestamp
from app_gateway.policy import ConfidentialClient
from app_gateway.session import AuthorizationScope, Session
from tests.auth_server.constants import (
    CLIENT_ID,
    IDP_ISSUER,
    IDP_SUBJECT,
    ISSUER,
    REQUEST_NONCE,
    TIME,
    USER_ID,
)

LIFETIME = timedelta(hours=1)


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("openid", True),
        ("profile openid email", True),
        ("profile email", False),
        (None, False),
    ],
)
def test_has_openid_scope(scope: str | None, *, expected: bool) -> None:
    assert has_openid_scope(AuthorizationScope(scope=scope)) is expected


def _decode_claims(
    session: Session,
    client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
    scope: str,
    nonce: str | None,
) -> dict[str, object]:
    token = create_id_token(
        session,
        client,
        AuthorizationScope(scope=scope),
        identity,
        signing_key,
        nonce,
        ISSUER,
        TIME + timedelta(minutes=10),
        LIFETIME,
    )
    decoded = jwt.decode(token, signing_key)
    assert decoded.header == {"alg": "ES256", "typ": "JWT", "kid": signing_key.kid}
    return dict(decoded.claims)


def test_create_id_token_openid_only(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    iat = to_timestamp(TIME + timedelta(minutes=10))

    claims = _decode_claims(
        session, confidential_client, identity, signing_key, "openid", None
    )

    assert claims == {
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": CLIENT_ID,
        "iat": iat,
        "exp": iat + int(LIFETIME.total_seconds()),
        "auth_time": to_timestamp(TIME),
    }


def test_create_id_token_with_nonce(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    claims = _decode_claims(
        session, confidential_client, identity, signing_key, "openid", REQUEST_NONCE
    )

    assert claims["nonce"] == REQUEST_NONCE


def test_create_id_token_email_scope(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    claims = _decode_claims(
        session, confidential_client, identity, signing_key, "openid email", None
    )

    assert claims["email"] == "user@example.test"
    assert "name" not in claims
    assert "idp_issuer" not in claims
    assert "idp_subject" not in claims


def test_create_id_token_profile_scope(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    claims = _decode_claims(
        session, confidential_client, identity, signing_key, "openid profile", None
    )

    assert claims["name"] == "Test User"
    assert claims["preferred_username"] == "testuser"
    assert claims["idp_issuer"] == IDP_ISSUER
    assert claims["idp_subject"] == IDP_SUBJECT
    assert "email" not in claims
    # Profile claims absent from the user's claims are omitted, not null.
    assert "given_name" not in claims
    assert "picture" not in claims


def test_create_id_token_profile_scope_omits_userinfo_only_claims(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    user = identity.user.model_copy(
        update={
            "claims": identity.user.claims
            | {"pronouns": "they/them", "picture": "https://example.test/u.png"}
        }
    )

    claims = _decode_claims(
        session,
        confidential_client,
        identity._replace(user=user),
        signing_key,
        "openid profile",
        None,
    )

    assert claims["name"] == "Test User"
    assert claims["preferred_username"] == "testuser"
    assert claims["idp_issuer"] == IDP_ISSUER
    assert claims["idp_subject"] == IDP_SUBJECT
    assert "pronouns" not in claims
    assert "picture" not in claims
