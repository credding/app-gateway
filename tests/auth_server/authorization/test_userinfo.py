import json
from datetime import timedelta
from http import HTTPStatus

import pytest
from fastapi import Response
from joserfc import jwk

from app_gateway.auth_server.authorization.userinfo import (
    check_userinfo_token,
    create_userinfo_response,
    invalid_token_response,
    parse_bearer_token,
)
from app_gateway.auth_server.grants.common import AccessTokenClaims, create_access_token
from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.common.clock import to_timestamp
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.policy import ConfidentialClient
from app_gateway.session import AuthorizationScope, Session
from tests.auth_server.constants import (
    CLIENT_ID,
    IDP_ISSUER,
    IDP_SUBJECT,
    ISSUER,
    KEY_ROTATION_SCHEDULE,
    RESOURCE,
    SCOPE,
    SESSION_ID,
    TIME,
    TOKEN_SIGNING_SEED,
    USER_ID,
)

LIFETIME = timedelta(hours=1)


@pytest.fixture
def keyset() -> jwk.KeySet:
    return get_token_signing_keyset(TOKEN_SIGNING_SEED, TIME, KEY_ROTATION_SCHEDULE)


def _access_token(
    session: Session,
    client: ConfidentialClient,
    signing_key: jwk.Key,
    scope: AuthorizationScope,
) -> str:
    return create_access_token(
        session,
        client,
        scope,
        signing_key,
        "jti",
        ISSUER,
        TIME,
        to_timestamp(TIME + LIFETIME),
    ).token


def _claims(scope: str | None = SCOPE) -> AccessTokenClaims:
    return AccessTokenClaims(
        sub=USER_ID,
        aud=CLIENT_ID,
        client_id=CLIENT_ID,
        sid=SESSION_ID,
        exp=to_timestamp(TIME + LIFETIME),
        scope=scope,
        act=None,
    )


def _assert_challenge(response: Response, status: int, challenge: str) -> None:
    assert response.status_code == status
    assert response.headers["www-authenticate"] == challenge
    assert response.headers["cache-control"] == "no-store"
    assert response.body == b""


def test_parse_bearer_token() -> None:
    assert parse_bearer_token("bearer  abc.def.ghi ") == "abc.def.ghi"


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic dXNlcjpwYXNz", "Bearerabc"],
    ids=["missing", "basic", "no-separator"],
)
def test_parse_bearer_token_missing(authorization: str | None) -> None:
    response = parse_bearer_token(authorization)

    assert isinstance(response, Response)
    _assert_challenge(response, HTTPStatus.UNAUTHORIZED, "Bearer")


def test_parse_bearer_token_empty() -> None:
    response = parse_bearer_token("Bearer  ")

    assert isinstance(response, Response)
    _assert_challenge(
        response, HTTPStatus.BAD_REQUEST, 'Bearer error="invalid_request"'
    )


def test_check_userinfo_token(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
) -> None:
    token = _access_token(
        session, confidential_client, signing_key, AuthorizationScope(scope=SCOPE)
    )

    assert check_userinfo_token(token, keyset, ISSUER, TIME) == _claims()


def test_check_userinfo_token_invalid(keyset: jwk.KeySet) -> None:
    response = check_userinfo_token("not-a-jwt", keyset, ISSUER, TIME)

    assert isinstance(response, Response)
    _assert_challenge(response, HTTPStatus.UNAUTHORIZED, 'Bearer error="invalid_token"')


def test_check_userinfo_token_resource_audience(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
) -> None:
    token = _access_token(
        session,
        confidential_client,
        signing_key,
        AuthorizationScope(resource=RESOURCE, scope=SCOPE),
    )

    response = check_userinfo_token(token, keyset, ISSUER, TIME)

    assert isinstance(response, Response)
    _assert_challenge(response, HTTPStatus.UNAUTHORIZED, 'Bearer error="invalid_token"')


@pytest.mark.parametrize("scope", [None, "profile email"])
def test_check_userinfo_token_insufficient_scope(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
    scope: str | None,
) -> None:
    token = _access_token(
        session, confidential_client, signing_key, AuthorizationScope(scope=scope)
    )

    response = check_userinfo_token(token, keyset, ISSUER, TIME)

    assert isinstance(response, Response)
    _assert_challenge(
        response,
        HTTPStatus.FORBIDDEN,
        'Bearer error="insufficient_scope", scope="openid"',
    )


def test_create_userinfo_response(session: Session, identity: UserIdentity) -> None:
    response = create_userinfo_response(_claims(), session, identity)

    assert response.status_code == HTTPStatus.OK
    assert response.headers["cache-control"] == "no-store"
    assert json.loads(bytes(response.body)) == {
        "sub": USER_ID,
        "name": "Test User",
        "preferred_username": "testuser",
        "email": "user@example.test",
        "idp_issuer": IDP_ISSUER,
        "idp_subject": IDP_SUBJECT,
    }


def test_create_userinfo_response_openid_only(
    session: Session, identity: UserIdentity
) -> None:
    response = create_userinfo_response(_claims("openid"), session, identity)

    assert json.loads(bytes(response.body)) == {"sub": USER_ID}


@pytest.mark.parametrize(
    "session_update",
    [{"revoked_at": TIME}, {"user_id": "user_other"}],
    ids=["revoked", "other-user"],
)
def test_create_userinfo_response_session_mismatch(
    session: Session, identity: UserIdentity, session_update: dict[str, object]
) -> None:
    response = create_userinfo_response(
        _claims(), session.model_copy(update=session_update), identity
    )

    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


@pytest.mark.parametrize("missing", ["session", "identity"])
def test_create_userinfo_response_missing(
    session: Session, identity: UserIdentity, missing: str
) -> None:
    response = create_userinfo_response(
        _claims(),
        None if missing == "session" else session,
        None if missing == "identity" else identity,
    )

    assert response.status_code == invalid_token_response().status_code
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
