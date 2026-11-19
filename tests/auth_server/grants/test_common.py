import base64
import json
from datetime import timedelta
from http import HTTPStatus
from types import SimpleNamespace

import pytest
from fastapi import Response
from joserfc import jwk, jwt

from app_gateway.auth_server.grants.common import (
    AuthenticateClientResult,
    ClientCredentials,
    CreateTokenResponseResult,
    ParseTokenRequestResult,
    TokenGrantResult,
    authenticate_client,
    create_token_response,
    narrow_request_scope,
    parse_client_credentials,
    parse_token_request,
)
from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.common.clock import to_timestamp
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import AuthorizationCodeTokenRequest, GrantType
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    ConfidentialClient,
    PublicClient,
)
from app_gateway.session import AuthorizationScope, Session
from app_gateway.session.schema import SessionGrantType
from tests.auth_server.constants import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    PUBLIC_CLIENT_ID,
    REDIRECT_URI,
    REQUEST_NONCE,
    RESOURCE,
    SCOPE,
    SESSION_ID,
    TIME,
    USER_ID,
)
from tests.auth_server.helpers import error_body


@pytest.fixture
def token_params(code_verifier: str, authorization_code: str) -> dict[str, str]:
    return {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "code_verifier": code_verifier,
        "redirect_uri": REDIRECT_URI,
    }


def test_parse_token_request_client_secret_post(
    token_params: dict[str, str],
    code_verifier: str,
    authorization_code: str,
) -> None:
    params = token_params | {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}

    result = parse_token_request(params, None)

    assert isinstance(result, ParseTokenRequestResult)
    assert result.request == AuthorizationCodeTokenRequest(
        grant_type=GrantType.AUTHORIZATION_CODE,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        code=authorization_code,
        code_verifier=code_verifier,
        redirect_uri=REDIRECT_URI,
    )
    assert result.credentials == ClientCredentials(
        CLIENT_ID, CLIENT_SECRET, basic=False
    )


def test_parse_token_request_client_secret_basic(
    token_params: dict[str, str],
) -> None:
    encoded = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    result = parse_token_request(token_params, f"Basic {encoded}")

    assert isinstance(result, ParseTokenRequestResult)
    assert isinstance(result.request, AuthorizationCodeTokenRequest)
    assert result.credentials == ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True)


def test_parse_token_request_public_client(token_params: dict[str, str]) -> None:
    result = parse_token_request(token_params | {"client_id": PUBLIC_CLIENT_ID}, None)

    assert isinstance(result, ParseTokenRequestResult)
    assert result.credentials == ClientCredentials(PUBLIC_CLIENT_ID, None, basic=False)


@pytest.mark.parametrize(
    ("client_id", "client_secret", "basic", "expected"),
    [
        (
            CLIENT_ID,
            CLIENT_SECRET,
            False,
            ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=False),
        ),
        (None, None, True, ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True)),
        (
            CLIENT_ID,
            None,
            True,
            ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True),
        ),
        (None, None, False, "invalid_client"),
        (None, CLIENT_SECRET, True, "invalid_request"),
        ("svc_other", None, True, "invalid_request"),
    ],
    ids=[
        "post",
        "basic",
        "basic-matching-id",
        "missing",
        "both-secrets",
        "id-mismatch",
    ],
)
def test_parse_client_credentials(
    client_id: str | None,
    client_secret: str | None,
    basic: bool,
    expected: ClientCredentials | str,
) -> None:
    encoded = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    result = parse_client_credentials(
        client_id, client_secret, f"Basic {encoded}" if basic else None
    )

    if isinstance(expected, ClientCredentials):
        assert result == expected
    else:
        assert isinstance(result, Response)
        assert error_body(result)["error"] == expected


def test_authenticate_confidential_client(
    confidential_client: ConfidentialClient,
    lifetime_settings: SimpleNamespace,
) -> None:
    credentials = ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True)

    result = authenticate_client(confidential_client, credentials, lifetime_settings)

    assert result == AuthenticateClientResult(
        confidential_client,
        lifetime_settings.confidential_client_session_lifetime,
        lifetime_settings.confidential_client_refresh_token_lifetime,
    )


def test_authenticate_public_client(
    public_client: PublicClient,
    lifetime_settings: SimpleNamespace,
) -> None:
    credentials = ClientCredentials(PUBLIC_CLIENT_ID, None, basic=False)

    result = authenticate_client(public_client, credentials, lifetime_settings)

    assert result == AuthenticateClientResult(
        public_client,
        lifetime_settings.public_client_session_lifetime,
        lifetime_settings.public_client_refresh_token_lifetime,
    )


def _token_request(**kwargs: str) -> AuthorizationCodeTokenRequest:
    return AuthorizationCodeTokenRequest(
        grant_type=GrantType.AUTHORIZATION_CODE,
        code="code",
        code_verifier="v" * 43,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("request_kwargs", "expected_scope"),
    [
        ({}, SCOPE),
        ({"scope": SCOPE}, SCOPE),
        ({"scope": "openid"}, "openid"),
        ({"resource": RESOURCE, "scope": "openid email"}, "openid email"),
    ],
    ids=["inherit", "same", "narrowed", "narrowed-with-resource"],
)
def test_narrow_request_scope(
    session: Session,
    confidential_client: ConfidentialClient,
    request_kwargs: dict[str, str],
    expected_scope: str,
) -> None:
    result = narrow_request_scope(
        session, confidential_client, _token_request(**request_kwargs), REQUEST_NONCE
    )

    assert result == TokenGrantResult(
        session,
        AuthorizationScope(resource=RESOURCE, scope=expected_scope),
        AccessType.AUTHENTICATED,
        REQUEST_NONCE,
    )


def test_narrow_request_scope_public_client(
    session: Session,
    public_client: PublicClient,
) -> None:
    result = narrow_request_scope(session, public_client, _token_request(), None)

    assert isinstance(result, TokenGrantResult)
    assert result.access_type is AccessType.PUBLIC


def test_create_token_response(
    session: Session,
    confidential_client: ConfidentialClient,
    request_scope: AuthorizationScope,
    access_rule: AppAccessRule,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    access_token_lifetime = 3600
    id_token_lifetime = 1800
    result = create_token_response(
        session,
        confidential_client,
        request_scope,
        access_rule,
        identity,
        REQUEST_NONCE,
        signing_key,
        "jti-123",
        "refresh-token",
        ISSUER,
        TIME,
        timedelta(seconds=access_token_lifetime),
        timedelta(seconds=id_token_lifetime),
    )

    assert isinstance(result, CreateTokenResponseResult)
    iat = to_timestamp(TIME)

    body = json.loads(bytes(result.response.body))
    assert result.response.status_code == HTTPStatus.OK
    assert result.response.headers["cache-control"] == "no-store"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == access_token_lifetime
    assert body["scope"] == SCOPE
    assert body["refresh_token"] == "refresh-token"

    access_token = jwt.decode(body["access_token"], signing_key)
    assert access_token.header == {
        "alg": "ES256",
        "typ": "at+jwt",
        "kid": signing_key.kid,
    }
    assert access_token.claims == {
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": RESOURCE,
        "client_id": CLIENT_ID,
        "sid": SESSION_ID,
        "iat": iat,
        "exp": iat + access_token_lifetime,
        "jti": "jti-123",
        "scope": SCOPE,
    }

    id_token = jwt.decode(body["id_token"], signing_key)
    assert id_token.header["typ"] == "JWT"
    assert id_token.claims["aud"] == CLIENT_ID
    assert id_token.claims["nonce"] == REQUEST_NONCE
    assert id_token.claims["exp"] == iat + id_token_lifetime

    log = result.access_token_log
    assert log.session_id == SESSION_ID
    assert log.scope == request_scope
    assert log.header == access_token.header
    assert log.claims == access_token.claims
    assert log.issued_at == TIME

    grant = result.refresh_token_grant
    assert grant.grant_type is SessionGrantType.REFRESH_TOKEN
    assert grant.token_hash == hash_token("refresh-token")
    assert grant.session_id == SESSION_ID
    assert grant.issued_at == TIME


def test_create_token_response_without_resource_or_openid(
    session: Session,
    confidential_client: ConfidentialClient,
    signing_key: jwk.Key,
) -> None:
    result = create_token_response(
        session,
        confidential_client,
        AuthorizationScope(),
        None,
        None,
        None,
        signing_key,
        "jti-123",
        "refresh-token",
        ISSUER,
        TIME,
        timedelta(hours=1),
        timedelta(hours=1),
    )

    assert isinstance(result, CreateTokenResponseResult)
    body = json.loads(bytes(result.response.body))
    assert "id_token" not in body
    assert "scope" not in body

    claims = jwt.decode(body["access_token"], signing_key).claims
    assert claims["aud"] == CLIENT_ID
    assert "scope" not in claims


def _basic(credentials: str) -> str:
    return f"Basic {base64.b64encode(credentials.encode()).decode()}"


@pytest.mark.parametrize(
    ("params_update", "authorization", "expected_error"),
    [
        (
            {"grant_type": "password", "client_id": CLIENT_ID},
            None,
            "unsupported_grant_type",
        ),
        ({"client_id": CLIENT_ID, "code": None}, None, "invalid_request"),
        ({"client_id": CLIENT_ID, "code_verifier": "short"}, None, "invalid_request"),
        ({}, None, "invalid_client"),
        (
            {"client_secret": CLIENT_SECRET},
            _basic(f"{CLIENT_ID}:{CLIENT_SECRET}"),
            "invalid_request",
        ),
        (
            {"client_id": "svc_other"},
            _basic(f"{CLIENT_ID}:{CLIENT_SECRET}"),
            "invalid_request",
        ),
    ],
    ids=[
        "unsupported-grant-type",
        "missing-code",
        "malformed-code-verifier",
        "no-client-id",
        "basic-and-body-secret",
        "basic-and-mismatched-client-id",
    ],
)
def test_parse_token_request_errors(
    token_params: dict[str, str],
    params_update: dict[str, str | None],
    authorization: str | None,
    expected_error: str,
) -> None:
    params = {k: v for k, v in (token_params | params_update).items() if v is not None}

    result = parse_token_request(params, authorization)

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result) == {"error": expected_error}
    assert "www-authenticate" not in result.headers


def test_parse_token_request_basic_with_matching_body_client_id(
    token_params: dict[str, str],
) -> None:
    result = parse_token_request(
        token_params | {"client_id": CLIENT_ID},
        _basic(f"{CLIENT_ID}:{CLIENT_SECRET}"),
    )

    assert isinstance(result, ParseTokenRequestResult)
    assert result.credentials == ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True)


def test_parse_token_request_basic_form_urlencoded(
    token_params: dict[str, str],
) -> None:
    # RFC 6749 Section 2.3.1: id and secret are form-urlencoded before base64.
    result = parse_token_request(token_params, _basic("svc%3Aid:s%2Bc+ret%3A"))

    assert isinstance(result, ParseTokenRequestResult)
    assert result.credentials == ClientCredentials("svc:id", "s+c ret:", basic=True)


def test_parse_token_request_basic_scheme_case_insensitive(
    token_params: dict[str, str],
) -> None:
    header = _basic(f"{CLIENT_ID}:{CLIENT_SECRET}").replace("Basic", "bAsIc")

    result = parse_token_request(token_params, header)

    assert isinstance(result, ParseTokenRequestResult)


@pytest.mark.parametrize(
    "authorization",
    [
        f"Bearer {base64.b64encode(b'a:b').decode()}",
        "Basic !!!not-base64!!!",
        _basic(f"{CLIENT_ID}{CLIENT_SECRET}"),
        _basic(f":{CLIENT_SECRET}"),
        "Basic",
    ],
    ids=["wrong-scheme", "bad-base64", "no-colon", "empty-client-id", "no-credentials"],
)
def test_parse_token_request_malformed_basic(
    token_params: dict[str, str], authorization: str
) -> None:
    result = parse_token_request(token_params, authorization)

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.UNAUTHORIZED
    assert result.headers["www-authenticate"] == 'Basic realm="token"'
    assert error_body(result) == {"error": "invalid_client"}


@pytest.mark.parametrize("basic", [True, False])
@pytest.mark.parametrize(
    ("client_fixture", "client_secret"),
    [
        ("confidential_client", "wrong-secret"),
        ("confidential_client", None),
        ("public_client", CLIENT_SECRET),
        (None, CLIENT_SECRET),
        (None, None),
    ],
    ids=[
        "confidential-wrong-secret",
        "confidential-no-secret",
        "public-with-secret",
        "unknown-client-with-secret",
        "unknown-client-no-secret",
    ],
)
def test_authenticate_client_errors(
    request: pytest.FixtureRequest,
    lifetime_settings: SimpleNamespace,
    client_fixture: str | None,
    client_secret: str | None,
    *,
    basic: bool,
) -> None:
    client = request.getfixturevalue(client_fixture) if client_fixture else None
    credentials = ClientCredentials(CLIENT_ID, client_secret, basic=basic)

    result = authenticate_client(client, credentials, lifetime_settings)

    assert isinstance(result, Response)
    assert error_body(result) == {"error": "invalid_client"}
    if basic:
        assert result.status_code == HTTPStatus.UNAUTHORIZED
        assert result.headers["www-authenticate"] == 'Basic realm="token"'
    else:
        assert result.status_code == HTTPStatus.BAD_REQUEST
        assert "www-authenticate" not in result.headers


@pytest.mark.parametrize(
    ("session_scope", "request_kwargs", "expected_error"),
    [
        (
            AuthorizationScope(resource=RESOURCE, scope=SCOPE),
            {"resource": "https://other.example.test"},
            "invalid_target",
        ),
        (AuthorizationScope(scope=SCOPE), {"resource": RESOURCE}, "invalid_target"),
        (
            AuthorizationScope(resource=RESOURCE, scope=SCOPE),
            {"scope": "openid offline_access"},
            "invalid_scope",
        ),
        (AuthorizationScope(resource=RESOURCE), {"scope": "openid"}, "invalid_scope"),
    ],
    ids=[
        "resource-mismatch",
        "resource-not-granted",
        "scope-widened",
        "no-granted-scope",
    ],
)
def test_narrow_request_scope_errors(
    session: Session,
    confidential_client: ConfidentialClient,
    session_scope: AuthorizationScope,
    request_kwargs: dict[str, str],
    expected_error: str,
) -> None:
    result = narrow_request_scope(
        session.model_copy(update={"scope": session_scope}),
        confidential_client,
        _token_request(**request_kwargs),
        None,
    )

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result) == {"error": expected_error}


def _create_token_response(
    session: Session,
    client: ConfidentialClient | PublicClient,
    request_scope: AuthorizationScope,
    access_rule: AppAccessRule | None,
    identity: UserIdentity | None,
    signing_key: jwk.Key,
) -> CreateTokenResponseResult | Response:
    return create_token_response(
        session,
        client,
        request_scope,
        access_rule,
        identity,
        None,
        signing_key,
        "jti-123",
        "refresh-token",
        ISSUER,
        TIME,
        timedelta(hours=1),
        timedelta(hours=1),
    )


def test_create_token_response_resource_without_access_rule(
    session: Session,
    confidential_client: ConfidentialClient,
    request_scope: AuthorizationScope,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    result = _create_token_response(
        session, confidential_client, request_scope, None, identity, signing_key
    )

    assert isinstance(result, Response)
    assert error_body(result) == {"error": "invalid_target"}


def test_create_token_response_openid_without_identity(
    session: Session,
    confidential_client: ConfidentialClient,
    request_scope: AuthorizationScope,
    access_rule: AppAccessRule,
    signing_key: jwk.Key,
) -> None:
    result = _create_token_response(
        session, confidential_client, request_scope, access_rule, None, signing_key
    )

    assert isinstance(result, Response)
    assert error_body(result) == {"error": "invalid_grant"}


def test_create_token_response_scope_without_openid(
    session: Session,
    confidential_client: ConfidentialClient,
    identity: UserIdentity,
    signing_key: jwk.Key,
) -> None:
    result = _create_token_response(
        session,
        confidential_client,
        AuthorizationScope(scope="email"),
        None,
        identity,
        signing_key,
    )

    assert isinstance(result, CreateTokenResponseResult)
    body = json.loads(bytes(result.response.body))
    assert body["scope"] == "email"
    assert "id_token" not in body
    assert jwt.decode(body["access_token"], signing_key).claims["scope"] == "email"


def test_create_token_response_public_client(
    session: Session,
    public_client: PublicClient,
    signing_key: jwk.Key,
) -> None:
    result = _create_token_response(
        session, public_client, AuthorizationScope(), None, None, signing_key
    )

    assert isinstance(result, CreateTokenResponseResult)
    body = json.loads(bytes(result.response.body))
    claims = jwt.decode(body["access_token"], signing_key).claims
    assert claims["aud"] == PUBLIC_CLIENT_ID
    assert claims["client_id"] == PUBLIC_CLIENT_ID
