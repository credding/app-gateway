import json
from datetime import timedelta
from http import HTTPStatus
from typing import Any

import pytest
from fastapi import Response
from joserfc import jwk, jwt

from app_gateway.auth_server.grants.common import create_access_token
from app_gateway.auth_server.grants.token_exchange import (
    MAX_ACT_DEPTH,
    CreateTokenExchangeResponseResult,
    SubjectToken,
    TokenExchangeGrant,
    check_token_exchange,
    create_token_exchange_response,
    decode_subject_token,
    exchange_access_type,
    narrow_exchange_scope,
)
from app_gateway.common.clock import to_timestamp
from app_gateway.common.jose import get_token_signing_key, get_token_signing_keyset
from app_gateway.crypto.key_management import normalize_time
from app_gateway.oauth import (
    GrantType,
    TokenExchangeTokenRequest,
    TokenExchangeTokenType,
)
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    Client,
    ConfidentialClient,
    PublicClient,
    Resource,
)
from app_gateway.session import AuthorizationScope, Session
from tests.auth_server.constants import (
    APP_ID,
    CLIENT_ID,
    CREATED_AT,
    ISSUER,
    KEY_ROTATION_SCHEDULE,
    PUBLIC_CLIENT_ID,
    RESOURCE,
    SCOPE,
    SESSION_ID,
    TIME,
    TOKEN_SIGNING_SEED,
    USER_ID,
)
from tests.auth_server.helpers import error_body

DOWNSTREAM_RESOURCE = "https://downstream.example.test"
RS_CLIENT_ID = "svc_rsclient"
LIFETIME = timedelta(hours=1)

_timestamps = {"created_at": CREATED_AT, "updated_at": CREATED_AT}


@pytest.fixture
def keyset() -> jwk.KeySet:
    return get_token_signing_keyset(TOKEN_SIGNING_SEED, TIME, KEY_ROTATION_SCHEDULE)


@pytest.fixture
def resource() -> Resource:
    return Resource(
        app_id=APP_ID,
        resource_id="res_test",
        name="Test API",
        uri=RESOURCE,
        **_timestamps,
    )


@pytest.fixture
def rs_client(confidential_client: ConfidentialClient) -> ConfidentialClient:
    """Another client in the app that owns RESOURCE: the resource server."""
    return confidential_client.model_copy(update={"client_id": RS_CLIENT_ID})


def _subject_token(
    session: Session,
    client: Client,
    signing_key: jwk.Key,
    *,
    resource: str | None = RESOURCE,
    scope: str | None = SCOPE,
    exp_offset: timedelta = LIFETIME,
    act: dict[str, Any] | None = None,
) -> str:
    return create_access_token(
        session,
        client,
        AuthorizationScope(resource=resource, scope=scope),
        signing_key,
        "subject-jti",
        ISSUER,
        TIME,
        to_timestamp(TIME + exp_offset),
        act,
    ).token


def _subject(
    *,
    client_id: str = CLIENT_ID,
    aud: str = RESOURCE,
    scope: str | None = SCOPE,
    exp_offset: timedelta = LIFETIME,
    act: dict[str, Any] | None = None,
) -> SubjectToken:
    return SubjectToken(
        sub=USER_ID,
        aud=aud,
        client_id=client_id,
        sid=SESSION_ID,
        exp=to_timestamp(TIME + exp_offset),
        scope=scope,
        act=act,
    )


def _request(**kwargs: str) -> TokenExchangeTokenRequest:
    return TokenExchangeTokenRequest.model_validate(
        {
            "grant_type": GrantType.TOKEN_EXCHANGE,
            "subject_token": "subject-token",
            "subject_token_type": TokenExchangeTokenType.ACCESS_TOKEN,
            "resource": DOWNSTREAM_RESOURCE,
        }
        | kwargs
    )


def _assert_error(result: object, error: str) -> None:
    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result) == {"error": error}


def test_decode_subject_token(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
) -> None:
    act = {"client_id": "svc_upstream"}
    token = _subject_token(session, confidential_client, signing_key, act=act)

    result = decode_subject_token(token, keyset, ISSUER, TIME)

    assert result == _subject(act=act)


def test_decode_subject_token_across_key_rotation(
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    rotation = normalize_time(TIME + KEY_ROTATION_SCHEDULE, KEY_ROTATION_SCHEDULE)
    issued_at = rotation - timedelta(minutes=1)
    decoded_at = rotation + timedelta(minutes=30)
    old_key = get_token_signing_key(
        TOKEN_SIGNING_SEED, issued_at, KEY_ROTATION_SCHEDULE
    )
    token = create_access_token(
        session,
        confidential_client,
        AuthorizationScope(resource=RESOURCE, scope=SCOPE),
        old_key,
        "subject-jti",
        ISSUER,
        issued_at,
        to_timestamp(issued_at + LIFETIME),
    ).token
    keyset = get_token_signing_keyset(
        TOKEN_SIGNING_SEED, decoded_at, KEY_ROTATION_SCHEDULE
    )

    result = decode_subject_token(token, keyset, ISSUER, decoded_at)

    assert isinstance(result, SubjectToken)


def _encode(
    signing_key: jwk.Key, header: dict[str, Any], claims: dict[str, Any]
) -> str:
    return jwt.encode(
        {"alg": "ES256", "kid": signing_key.kid} | header, claims, signing_key
    )


@pytest.mark.parametrize(
    ("header", "claims_update", "claims_drop"),
    [
        ({"typ": "JWT"}, {}, ()),
        ({"typ": "at+jwt"}, {"iss": "https://evil.example.test"}, ()),
        ({"typ": "at+jwt"}, {"exp": to_timestamp(TIME) - 1}, ()),
        ({"typ": "at+jwt"}, {}, ("sid",)),
        ({"typ": "at+jwt"}, {}, ("client_id",)),
        ({"typ": "at+jwt"}, {"aud": [RESOURCE]}, ()),
        ({"typ": "at+jwt"}, {"act": "svc_x"}, ()),
        ({"typ": "at+jwt"}, {"scope": ["openid"]}, ()),
    ],
    ids=[
        "id-token-typ",
        "wrong-iss",
        "expired",
        "missing-sid",
        "missing-client-id",
        "list-aud",
        "non-object-act",
        "non-string-scope",
    ],
)
def test_decode_subject_token_errors(
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
    header: dict[str, Any],
    claims_update: dict[str, Any],
    claims_drop: tuple[str, ...],
) -> None:
    iat = to_timestamp(TIME)
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": RESOURCE,
        "client_id": CLIENT_ID,
        "sid": SESSION_ID,
        "iat": iat,
        "exp": iat + 3600,
        "jti": "subject-jti",
    } | claims_update
    for name in claims_drop:
        del claims[name]

    result = decode_subject_token(
        _encode(signing_key, header, claims), keyset, ISSUER, TIME
    )

    _assert_error(result, "invalid_grant")


def test_decode_subject_token_foreign_key(
    session: Session,
    confidential_client: ConfidentialClient,
    keyset: jwk.KeySet,
) -> None:
    foreign_key = get_token_signing_key(
        b"some-other-signing-seed-0123456789", TIME, KEY_ROTATION_SCHEDULE
    )
    token = _subject_token(session, confidential_client, foreign_key)

    _assert_error(decode_subject_token(token, keyset, ISSUER, TIME), "invalid_grant")


def test_decode_subject_token_garbage(keyset: jwk.KeySet) -> None:
    _assert_error(
        decode_subject_token("not-a-jwt", keyset, ISSUER, TIME), "invalid_grant"
    )


def test_check_token_exchange_self_reaudience(
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    result = check_token_exchange(
        _subject(),
        session,
        None,
        confidential_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert result == TokenExchangeGrant(
        session,
        DOWNSTREAM_RESOURCE,
        AuthorizationScope(resource=DOWNSTREAM_RESOURCE, scope=SCOPE),
        None,
        to_timestamp(TIME + LIFETIME),
    )


def test_check_token_exchange_self_keeps_existing_act(
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    act = {"client_id": "svc_upstream"}

    result = check_token_exchange(
        _subject(act=act),
        session,
        None,
        confidential_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)
    assert result.act == act


def test_check_token_exchange_same_app_resource_server(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
) -> None:
    result = check_token_exchange(
        _subject(),
        session,
        resource,
        rs_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)
    assert result.act == {"client_id": RS_CLIENT_ID}


def test_check_token_exchange_nests_act(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
) -> None:
    prior = {"client_id": "svc_upstream"}

    result = check_token_exchange(
        _subject(act=prior),
        session,
        resource,
        rs_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)
    assert result.act == {"client_id": RS_CLIENT_ID, "act": prior}


def test_check_token_exchange_act_depth_limit(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
) -> None:
    act: dict[str, Any] | None = None
    for i in range(MAX_ACT_DEPTH):
        act = {"client_id": f"svc_{i}"} | ({"act": act} if act else {})

    result = check_token_exchange(
        _subject(act=act),
        session,
        resource,
        rs_client,
        _request(),
        TIME,
        LIFETIME,
    )

    _assert_error(result, "invalid_request")


def test_check_token_exchange_caps_exp_at_subject(
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    result = check_token_exchange(
        _subject(exp_offset=timedelta(minutes=5)),
        session,
        None,
        confidential_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)
    assert result.expires_at == to_timestamp(TIME + timedelta(minutes=5))


def test_check_token_exchange_public_client_on_behalf_of(
    session: Session,
    resource: Resource,
    public_client: PublicClient,
) -> None:
    """Public clients can't act on behalf of a user, even for their app's resource."""
    result = check_token_exchange(
        _subject(),
        session,
        resource,
        public_client,
        _request(),
        TIME,
        LIFETIME,
    )

    _assert_error(result, "unauthorized_client")


def test_check_token_exchange_public_then_confidential_hop(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
) -> None:
    """public A -> confidential B -> C still works."""
    result = check_token_exchange(
        _subject(client_id=PUBLIC_CLIENT_ID),
        session,
        resource,
        rs_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)
    assert result.act == {"client_id": RS_CLIENT_ID}


def test_check_token_exchange_public_client_self(
    session: Session,
    public_client: PublicClient,
) -> None:
    result = check_token_exchange(
        _subject(client_id=PUBLIC_CLIENT_ID),
        session,
        None,
        public_client,
        _request(),
        TIME,
        LIFETIME,
    )

    assert isinstance(result, TokenExchangeGrant)


@pytest.mark.parametrize(
    ("request_kwargs", "expected_error"),
    [
        ({"audience": "downstream"}, "invalid_request"),
        ({"actor_token": "actor"}, "invalid_request"),
        ({"actor_token_type": TokenExchangeTokenType.ACCESS_TOKEN}, "invalid_request"),
        ({"scope": "openid admin"}, "invalid_scope"),
    ],
    ids=["audience", "actor-token", "actor-token-type", "wider-scope"],
)
def test_check_token_exchange_request_errors(
    session: Session,
    confidential_client: ConfidentialClient,
    request_kwargs: dict[str, str],
    expected_error: str,
) -> None:
    result = check_token_exchange(
        _subject(),
        session,
        None,
        confidential_client,
        _request(**request_kwargs),
        TIME,
        LIFETIME,
    )

    _assert_error(result, expected_error)


def test_check_token_exchange_requires_resource(
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    request = _request().model_copy(update={"resource": None})

    result = check_token_exchange(
        _subject(), session, None, confidential_client, request, TIME, LIFETIME
    )

    _assert_error(result, "invalid_request")


@pytest.mark.parametrize(
    "session_update",
    [None, {"revoked_at": TIME}, {"user_id": "user_other"}],
    ids=["missing", "revoked", "other-user"],
)
def test_check_token_exchange_session_errors(
    session: Session,
    confidential_client: ConfidentialClient,
    session_update: dict[str, Any] | None,
) -> None:
    maybe_session = (
        None if session_update is None else session.model_copy(update=session_update)
    )

    result = check_token_exchange(
        _subject(),
        maybe_session,
        None,
        confidential_client,
        _request(),
        TIME,
        LIFETIME,
    )

    _assert_error(result, "invalid_grant")


@pytest.mark.parametrize(
    ("resource_update", "use_resource"),
    [
        (None, False),
        ({"app_id": "app_other"}, True),
        ({"uri": DOWNSTREAM_RESOURCE}, True),
    ],
    ids=["aud-not-a-resource", "foreign-app", "resource-uri-mismatch"],
)
def test_check_token_exchange_unauthorized_requester(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
    resource_update: dict[str, str] | None,
    use_resource: bool,
) -> None:
    maybe_resource = (
        resource.model_copy(update=resource_update or {}) if use_resource else None
    )

    result = check_token_exchange(
        _subject(),
        session,
        maybe_resource,
        rs_client,
        _request(),
        TIME,
        LIFETIME,
    )

    _assert_error(result, "invalid_grant")


@pytest.mark.parametrize(
    ("client_fixture", "act", "expected"),
    [
        ("confidential_client", None, AccessType.AUTHENTICATED),
        ("public_client", None, AccessType.PUBLIC),
        ("rs_client", {"client_id": RS_CLIENT_ID}, AccessType.DELEGATED),
    ],
    ids=["self-confidential", "self-public", "delegated"],
)
def test_exchange_access_type(
    request: pytest.FixtureRequest,
    session: Session,
    client_fixture: str,
    act: dict[str, Any] | None,
    expected: AccessType,
) -> None:
    client = request.getfixturevalue(client_fixture)
    grant = TokenExchangeGrant(
        session,
        DOWNSTREAM_RESOURCE,
        AuthorizationScope(resource=DOWNSTREAM_RESOURCE, scope=SCOPE),
        act,
        to_timestamp(TIME + LIFETIME),
    )

    assert exchange_access_type(grant, client) is expected


def test_exchange_access_type_self_hop_after_delegation_stays_delegated(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
) -> None:
    """B acts for the user, then re-audiences its own delegated token to C.

    The second hop is a self exchange, but it must still need a DELEGATED rule
    at C rather than B's direct-access rule.
    """
    first = check_token_exchange(
        _subject(), session, resource, rs_client, _request(), TIME, LIFETIME
    )
    assert isinstance(first, TokenExchangeGrant)
    assert first.act == {"client_id": RS_CLIENT_ID}

    second = check_token_exchange(
        _subject(client_id=RS_CLIENT_ID, aud=DOWNSTREAM_RESOURCE, act=first.act),
        session,
        None,
        rs_client,
        _request(resource="https://c.example.test"),
        TIME,
        LIFETIME,
    )
    assert isinstance(second, TokenExchangeGrant)
    assert second.act == first.act

    assert exchange_access_type(second, rs_client) is AccessType.DELEGATED


@pytest.mark.parametrize(
    ("subject_scope", "requested_scope", "expected"),
    [
        (SCOPE, None, SCOPE),
        (None, None, None),
        (SCOPE, "openid", "openid"),
        (SCOPE, SCOPE, SCOPE),
    ],
)
def test_narrow_exchange_scope(
    subject_scope: str | None,
    requested_scope: str | None,
    expected: str | None,
) -> None:
    assert narrow_exchange_scope(subject_scope, requested_scope) == expected


@pytest.mark.parametrize(
    ("subject_scope", "requested_scope"),
    [(None, "openid"), ("openid", "openid email")],
)
def test_narrow_exchange_scope_errors(
    subject_scope: str | None, requested_scope: str
) -> None:
    _assert_error(
        narrow_exchange_scope(subject_scope, requested_scope), "invalid_scope"
    )


def test_create_token_exchange_response(
    session: Session,
    rs_client: ConfidentialClient,
    access_rule: AppAccessRule,
    signing_key: jwk.Key,
) -> None:
    expires_at = to_timestamp(TIME) + 600
    grant = TokenExchangeGrant(
        session,
        DOWNSTREAM_RESOURCE,
        AuthorizationScope(resource=DOWNSTREAM_RESOURCE, scope="openid"),
        {"client_id": RS_CLIENT_ID},
        expires_at,
    )

    result = create_token_exchange_response(
        grant, rs_client, access_rule, signing_key, "jti-456", ISSUER, TIME
    )

    assert isinstance(result, CreateTokenExchangeResponseResult)
    assert result.response.status_code == HTTPStatus.OK
    assert result.response.headers["cache-control"] == "no-store"

    body = json.loads(bytes(result.response.body))
    access_token = body.pop("access_token")
    assert body == {
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 600,
        "scope": "openid",
    }

    token = jwt.decode(access_token, signing_key)
    assert token.header == {"alg": "ES256", "typ": "at+jwt", "kid": signing_key.kid}
    assert token.claims == {
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": DOWNSTREAM_RESOURCE,
        "client_id": RS_CLIENT_ID,
        "sid": SESSION_ID,
        "iat": to_timestamp(TIME),
        "exp": expires_at,
        "jti": "jti-456",
        "scope": "openid",
        "act": {"client_id": RS_CLIENT_ID},
    }

    log = result.access_token_log
    assert log.session_id == SESSION_ID
    assert log.scope == grant.request_scope
    assert log.claims == token.claims
    assert log.issued_at == TIME


def test_create_token_exchange_response_without_access_rule(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
) -> None:
    grant = TokenExchangeGrant(
        session,
        DOWNSTREAM_RESOURCE,
        AuthorizationScope(resource=DOWNSTREAM_RESOURCE, scope=SCOPE),
        None,
        to_timestamp(TIME + LIFETIME),
    )

    result = create_token_exchange_response(
        grant, confidential_client, None, signing_key, "jti", ISSUER, TIME
    )

    _assert_error(result, "invalid_target")


def test_exchanged_token_round_trips_as_subject(
    session: Session,
    resource: Resource,
    rs_client: ConfidentialClient,
    access_rule: AppAccessRule,
    signing_key: jwk.Key,
    keyset: jwk.KeySet,
    confidential_client: ConfidentialClient,
) -> None:
    """An exchanged token can itself be decoded as a subject token (chaining)."""
    subject_token = _subject_token(session, confidential_client, signing_key)
    subject = decode_subject_token(subject_token, keyset, ISSUER, TIME)
    assert isinstance(subject, SubjectToken)

    grant = check_token_exchange(
        subject, session, resource, rs_client, _request(), TIME, LIFETIME
    )
    assert isinstance(grant, TokenExchangeGrant)
    issued = create_token_exchange_response(
        grant, rs_client, access_rule, signing_key, "jti-2", ISSUER, TIME
    )
    assert isinstance(issued, CreateTokenExchangeResponseResult)

    exchanged = json.loads(bytes(issued.response.body))["access_token"]
    second = decode_subject_token(exchanged, keyset, ISSUER, TIME)

    assert second == _subject(
        client_id=RS_CLIENT_ID,
        aud=DOWNSTREAM_RESOURCE,
        act={"client_id": RS_CLIENT_ID},
    )
