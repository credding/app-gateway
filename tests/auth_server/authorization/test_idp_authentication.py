from datetime import timedelta
from http import HTTPStatus

import pytest
from fastapi import Response

from app_gateway.auth_server.authorization.idp_authentication import (
    AuthorizationCodeTokenRequestResult,
    CreateIdpAuthorizationRedirectResult,
    ParseAuthorizationCallbackResponseResult,
    ParseAuthorizationRequestResult,
    create_authorization_code_response_redirect,
    create_idp_authorization_code_token_request,
    create_idp_authorization_redirect,
    create_idp_session,
    parse_authorization_callback_response,
    parse_authorization_callback_state_token,
    parse_authorization_request,
    parse_authorization_request_client_id,
)
from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
)
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import (
    AuthorizationRequest,
    CodeChallengeMethod,
    GrantType,
    ResponseType,
    TokenResponse,
    compute_code_challenge,
)
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    AppIdentityProvider,
    IdentityProvider,
    PublicClient,
    User,
)
from app_gateway.session import (
    AuthorizationScope,
    AuthorizationState,
    IdpAuthorizationState,
    decrypt_idp_refresh_token,
)
from app_gateway.session.schema import SessionGrantType
from tests.auth_server.constants import (
    CALLBACK_URL,
    CLIENT_ID,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_ISSUER,
    ISSUER,
    NONCE_BYTES,
    PUBLIC_CLIENT_ID,
    REDIRECT_URI,
    REQUEST_NONCE,
    REQUEST_STATE,
    RESOURCE,
    SCOPE,
    SECRET_ENC_KEY,
    SESSION_ID,
    TIME,
    USER_ID,
)
from tests.auth_server.helpers import error_body, redirect_location

STATE_LIFETIME = timedelta(minutes=5)


def test_parse_authorization_request_client_id(
    authorize_params: dict[str, str],
) -> None:
    assert parse_authorization_request_client_id(authorize_params) == CLIENT_ID


def test_parse_authorization_request(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    code_challenge: str,
    app_idp: AppIdentityProvider,
    idp: IdentityProvider,
) -> None:
    result = parse_authorization_request(client_app_idps, authorize_params, ISSUER)

    assert isinstance(result, ParseAuthorizationRequestResult)
    assert result.request == AuthorizationRequest(
        response_type=ResponseType.CODE,
        client_id=CLIENT_ID,
        code_challenge=code_challenge,
        code_challenge_method=CodeChallengeMethod.S256,
        redirect_uri=REDIRECT_URI,
        resource=RESOURCE,
        scope=SCOPE,
        state=REQUEST_STATE,
        nonce=REQUEST_NONCE,
    )
    assert result.app_idp == app_idp
    assert result.idp == idp
    assert result.access_type is AccessType.AUTHENTICATED


def test_parse_authorization_request_public_client(
    public_client: PublicClient,
    app_idp_idp: AppIdpIdentityProvider,
    authorize_params: dict[str, str],
) -> None:
    params = authorize_params | {"client_id": PUBLIC_CLIENT_ID}

    result = parse_authorization_request(
        ClientAppIdentityProviders(public_client, [app_idp_idp]), params, ISSUER
    )

    assert isinstance(result, ParseAuthorizationRequestResult)
    assert result.access_type is AccessType.PUBLIC


def test_parse_authorization_request_confidential_client_without_pkce(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
) -> None:
    params = {
        k: v
        for k, v in authorize_params.items()
        if k not in {"code_challenge", "code_challenge_method"}
    }

    result = parse_authorization_request(client_app_idps, params, ISSUER)

    assert isinstance(result, ParseAuthorizationRequestResult)
    assert result.request.code_challenge is None
    assert result.request.code_challenge_method is None


@pytest.mark.parametrize(
    ("client_fixture", "omitted"),
    [
        ("public_client", {"code_challenge", "code_challenge_method"}),
        ("public_client", {"code_challenge"}),
        ("public_client", {"code_challenge_method"}),
        ("confidential_client", {"code_challenge"}),
        ("confidential_client", {"code_challenge_method"}),
    ],
    ids=[
        "public-without-pkce",
        "public-without-challenge",
        "public-without-method",
        "confidential-without-challenge",
        "confidential-without-method",
    ],
)
def test_parse_authorization_request_pkce_invalid(
    request: pytest.FixtureRequest,
    app_idp_idp: AppIdpIdentityProvider,
    authorize_params: dict[str, str],
    client_fixture: str,
    omitted: set[str],
) -> None:
    client = request.getfixturevalue(client_fixture)
    params = {
        k: v
        for k, v in (authorize_params | {"client_id": client.client_id}).items()
        if k not in omitted
    }

    result = parse_authorization_request(
        ClientAppIdentityProviders(client, [app_idp_idp]), params, ISSUER
    )

    _assert_error_redirect(result, "invalid_request")


def test_parse_authorization_request_minimal(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
) -> None:
    params = {
        k: v
        for k, v in authorize_params.items()
        if k not in {"resource", "scope", "nonce"}
    }

    result = parse_authorization_request(client_app_idps, params, ISSUER)

    assert isinstance(result, ParseAuthorizationRequestResult)
    assert result.request.resource is None
    assert result.request.scope is None
    assert result.request.nonce is None


@pytest.mark.parametrize("with_resource", [True, False])
def test_create_idp_authorization_redirect(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    app_idp: AppIdentityProvider,
    idp: IdentityProvider,
    access_rule: AppAccessRule,
    request_state: AuthorizationState,
    idp_code_verifier: str,
    *,
    with_resource: bool,
) -> None:
    if not with_resource:
        del authorize_params["resource"]
    parsed = parse_authorization_request(client_app_idps, authorize_params, ISSUER)
    assert isinstance(parsed, ParseAuthorizationRequestResult)

    result = create_idp_authorization_redirect(
        parsed.request,
        app_idp,
        idp,
        access_rule if with_resource else None,
        "idp-state",
        idp_code_verifier,
        CALLBACK_URL,
        TIME,
        ISSUER,
    )

    assert isinstance(result, CreateIdpAuthorizationRedirectResult)
    assert result.state == IdpAuthorizationState(
        state_hash=hash_token("idp-state"),
        client_id=CLIENT_ID,
        request_scope=AuthorizationScope(
            resource=RESOURCE if with_resource else None, scope=SCOPE
        ),
        request_state=request_state,
        idp_slug=idp.slug,
        idp_issuer=IDP_ISSUER,
        code_verifier=idp_code_verifier,
        issued_at=TIME,
    )

    assert result.response.status_code == HTTPStatus.SEE_OTHER
    assert result.response.headers["cache-control"] == "no-store"
    location, params = redirect_location(result.response)
    assert location == idp.authorization_endpoint
    assert params == {
        "response_type": "code",
        "client_id": IDP_CLIENT_ID,
        "code_challenge": compute_code_challenge(idp_code_verifier),
        "code_challenge_method": "S256",
        "redirect_uri": CALLBACK_URL,
        "state": "idp-state",
    }


def test_parse_authorization_callback_state_token() -> None:
    params = {"code": "idp-code", "state": "idp-state"}

    assert parse_authorization_callback_state_token(params) == "idp-state"


@pytest.mark.parametrize(
    "params",
    [
        {"code": "idp-code", "state": "idp-state", "iss": IDP_ISSUER},
        {"code": "idp-code", "state": "idp-state"},
    ],
    ids=["with-iss", "without-iss"],
)
def test_parse_authorization_callback_response(
    idp_authorization_state: IdpAuthorizationState,
    params: dict[str, str],
) -> None:
    result = parse_authorization_callback_response(
        idp_authorization_state,
        params,
        TIME + STATE_LIFETIME - timedelta(microseconds=1),
        ISSUER,
        STATE_LIFETIME,
    )

    assert result == ParseAuthorizationCallbackResponseResult(
        idp_authorization_state, "idp-code"
    )


def test_create_idp_authorization_code_token_request(
    app_idp_idp: AppIdpIdentityProvider,
    idp: IdentityProvider,
    idp_authorization_state: IdpAuthorizationState,
) -> None:
    result = create_idp_authorization_code_token_request(
        app_idp_idp,
        idp_authorization_state,
        "idp-code",
        CALLBACK_URL,
        ISSUER,
        SECRET_ENC_KEY,
    )

    assert isinstance(result, AuthorizationCodeTokenRequestResult)
    assert result.idp == idp
    request = result.request
    assert request.grant_type is GrantType.AUTHORIZATION_CODE
    assert request.client_id == IDP_CLIENT_ID
    assert request.client_secret == IDP_CLIENT_SECRET
    assert request.code == "idp-code"
    assert request.code_verifier == idp_authorization_state.code_verifier
    assert request.redirect_uri == CALLBACK_URL


def test_create_idp_session() -> None:
    token_response = TokenResponse(
        access_token="idp-access-token",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="idp-refresh-token",
    )

    idp_session = create_idp_session(
        CLIENT_ID,
        USER_ID,
        IDP_ISSUER,
        token_response,
        TIME,
        SECRET_ENC_KEY,
        NONCE_BYTES,
    )

    assert idp_session.client_id == CLIENT_ID
    assert idp_session.user_id == USER_ID
    assert idp_session.idp_issuer == IDP_ISSUER
    assert idp_session.expires_in == timedelta(hours=1)
    assert idp_session.issued_at == TIME
    assert decrypt_idp_refresh_token(SECRET_ENC_KEY, idp_session) == "idp-refresh-token"


def test_create_idp_session_keeps_previous_refresh_token() -> None:
    token_response = TokenResponse(
        access_token="idp-access-token",
        token_type="Bearer",
    )

    idp_session = create_idp_session(
        CLIENT_ID,
        USER_ID,
        IDP_ISSUER,
        token_response,
        TIME,
        SECRET_ENC_KEY,
        NONCE_BYTES,
        previous_refresh_token_enc=b"previous",
    )

    assert idp_session.expires_in is None
    assert idp_session.refresh_token_enc == b"previous"


def test_create_authorization_code_response_redirect(
    idp_authorization_state: IdpAuthorizationState,
    user: User,
    request_scope: AuthorizationScope,
    request_state: AuthorizationState,
    authorization_code: str,
) -> None:
    session, session_grant, response = create_authorization_code_response_redirect(
        idp_authorization_state,
        user,
        SESSION_ID,
        authorization_code,
        ISSUER,
        TIME,
    )

    assert session.session_id == SESSION_ID
    assert session.client_id == CLIENT_ID
    assert session.user_id == USER_ID
    assert session.idp_issuer == IDP_ISSUER
    assert session.scope == request_scope
    assert session.issued_at == TIME
    assert session.revoked_at is None

    assert session_grant.grant_type is SessionGrantType.AUTHORIZATION_CODE
    assert session_grant.token_hash == hash_token(authorization_code)
    assert session_grant.session_id == SESSION_ID
    assert session_grant.state == request_state
    assert session_grant.issued_at == TIME
    assert session_grant.invalidated_at is None

    assert response.status_code == HTTPStatus.SEE_OTHER
    location, params = redirect_location(response)
    assert location == REDIRECT_URI
    assert params == {"code": authorization_code, "state": REQUEST_STATE, "iss": ISSUER}


def _assert_error_response(result: object, error: str) -> None:
    """A 400 JSON error, never a redirect to an unverified redirect_uri."""
    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert "location" not in result.headers
    assert error_body(result) == {"error": error, "iss": ISSUER}


def _assert_error_redirect(
    result: object, error: str, state: str | None = REQUEST_STATE
) -> None:
    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.SEE_OTHER
    location, params = redirect_location(result)
    assert location == REDIRECT_URI
    expected = {"error": error, "iss": ISSUER}
    if state is not None:
        expected["state"] = state
    assert params == expected


def test_parse_authorization_request_client_id_repeated() -> None:
    assert parse_authorization_request_client_id({"client_id": ["a", "b"]}) is None


def test_parse_authorization_request_unknown_client(
    authorize_params: dict[str, str],
) -> None:
    result = parse_authorization_request(None, authorize_params, ISSUER)

    _assert_error_response(result, "unauthorized_client")


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://attacker.example.test/callback",
        f"{REDIRECT_URI}/extra",
        None,
        [REDIRECT_URI, "https://attacker.example.test/callback"],
    ],
    ids=["unregistered", "prefix-match", "missing", "repeated"],
)
def test_parse_authorization_request_bad_redirect_uri(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    redirect_uri: str | list[str] | None,
) -> None:
    params: dict[str, object] = dict(authorize_params)
    if redirect_uri is None:
        del params["redirect_uri"]
    else:
        params["redirect_uri"] = redirect_uri

    result = parse_authorization_request(client_app_idps, params, ISSUER)

    _assert_error_response(result, "unauthorized_client")


@pytest.mark.parametrize(
    ("params_update", "expected_error"),
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"resource": [RESOURCE, "https://other.example.test"]}, "invalid_target"),
        ({"code_challenge": None}, "invalid_request"),
        ({"code_challenge": "too-short"}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"response_type": "token", "code_challenge": "too-short"}, "invalid_request"),
    ],
    ids=[
        "unsupported-response-type",
        "repeated-resource",
        "missing-code-challenge",
        "malformed-code-challenge",
        "plain-pkce",
        "multiple-errors",
    ],
)
def test_parse_authorization_request_invalid(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    params_update: dict[str, object],
    expected_error: str,
) -> None:
    params = {
        k: v for k, v in (authorize_params | params_update).items() if v is not None
    }

    result = parse_authorization_request(client_app_idps, params, ISSUER)

    _assert_error_redirect(result, expected_error)


@pytest.mark.parametrize(
    "state",
    [None, "", ["a", "b"]],
    ids=["missing", "empty", "repeated"],
)
def test_parse_authorization_request_bad_state(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    state: str | list[str] | None,
) -> None:
    params: dict[str, object] = dict(authorize_params)
    if state is None:
        del params["state"]
    else:
        params["state"] = state

    result = parse_authorization_request(client_app_idps, params, ISSUER)

    # A missing or repeated state isn't echoed back. (An empty one is sent as
    # "state=", which redirect_location's parse_qs drops as blank.)
    _assert_error_redirect(result, "invalid_request", state=None)


@pytest.mark.parametrize(
    ("app_idp_count", "expected_error"),
    [(0, "unauthorized_client"), (2, "server_error")],
    ids=["no-idp", "ambiguous-idp"],
)
def test_parse_authorization_request_idp_count(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    authorize_params: dict[str, str],
    app_idp_count: int,
    expected_error: str,
) -> None:
    result = parse_authorization_request(
        ClientAppIdentityProviders(
            client_app_idps.client, [app_idp_idp] * app_idp_count
        ),
        authorize_params,
        ISSUER,
    )

    _assert_error_redirect(result, expected_error)


def test_create_idp_authorization_redirect_resource_without_access_rule(
    client_app_idps: ClientAppIdentityProviders,
    authorize_params: dict[str, str],
    app_idp: AppIdentityProvider,
    idp: IdentityProvider,
    idp_code_verifier: str,
) -> None:
    parsed = parse_authorization_request(client_app_idps, authorize_params, ISSUER)
    assert isinstance(parsed, ParseAuthorizationRequestResult)

    result = create_idp_authorization_redirect(
        parsed.request,
        app_idp,
        idp,
        None,
        "idp-state",
        idp_code_verifier,
        CALLBACK_URL,
        TIME,
        ISSUER,
    )

    _assert_error_redirect(result, "invalid_target")


def test_parse_authorization_callback_state_token_repeated() -> None:
    assert parse_authorization_callback_state_token({"state": ["a", "b"]}) is None


def test_parse_authorization_callback_response_unknown_state() -> None:
    result = parse_authorization_callback_response(
        None, {"code": "idp-code"}, TIME, ISSUER, STATE_LIFETIME
    )

    _assert_error_response(result, "invalid_request")


def test_parse_authorization_callback_response_expired_state(
    idp_authorization_state: IdpAuthorizationState,
) -> None:
    result = parse_authorization_callback_response(
        idp_authorization_state,
        {"code": "idp-code"},
        # Expires at exactly its lifetime, like codes and refresh tokens.
        TIME + STATE_LIFETIME,
        ISSUER,
        STATE_LIFETIME,
    )

    _assert_error_response(result, "invalid_request")


def test_parse_authorization_callback_response_iss_mismatch(
    idp_authorization_state: IdpAuthorizationState,
) -> None:
    result = parse_authorization_callback_response(
        idp_authorization_state,
        {"code": "idp-code", "iss": "https://other-idp.example.test"},
        TIME,
        ISSUER,
        STATE_LIFETIME,
    )

    # Mix-up defense: a response from the wrong IdP isn't forwarded to the client.
    _assert_error_response(result, "invalid_request")


@pytest.mark.parametrize(
    ("params", "expected_error"),
    [
        ({"error": "access_denied"}, "access_denied"),
        ({"error": "temporarily_unavailable"}, "temporarily_unavailable"),
        ({"error": "invalid_scope"}, "server_error"),
        ({"error": "made_up_error"}, "server_error"),
        ({}, "server_error"),
        ({"error": ["access_denied", "access_denied"]}, "server_error"),
        ({"code": ["idp-code", "idp-code-2"]}, "server_error"),
    ],
    ids=[
        "access-denied",
        "temporarily-unavailable",
        "other-error",
        "unknown-error",
        "no-code-or-error",
        "repeated-error",
        "repeated-code",
    ],
)
def test_parse_authorization_callback_response_idp_error(
    idp_authorization_state: IdpAuthorizationState,
    params: dict[str, object],
    expected_error: str,
) -> None:
    result = parse_authorization_callback_response(
        idp_authorization_state, params, TIME, ISSUER, STATE_LIFETIME
    )

    _assert_error_redirect(result, expected_error)


def test_create_idp_authorization_code_token_request_app_idp_missing(
    idp_authorization_state: IdpAuthorizationState,
) -> None:
    result = create_idp_authorization_code_token_request(
        None,
        idp_authorization_state,
        "idp-code",
        CALLBACK_URL,
        ISSUER,
        SECRET_ENC_KEY,
    )

    _assert_error_redirect(result, "server_error")


def test_create_idp_session_without_any_refresh_token() -> None:
    idp_session = create_idp_session(
        CLIENT_ID,
        USER_ID,
        IDP_ISSUER,
        TokenResponse(access_token="idp-access-token", token_type="Bearer"),
        TIME,
        SECRET_ENC_KEY,
        NONCE_BYTES,
    )

    assert idp_session.refresh_token_enc is None


def test_create_idp_session_replaces_previous_refresh_token() -> None:
    idp_session = create_idp_session(
        CLIENT_ID,
        USER_ID,
        IDP_ISSUER,
        TokenResponse(
            access_token="idp-access-token",
            token_type="Bearer",
            refresh_token="rotated-refresh-token",
        ),
        TIME,
        SECRET_ENC_KEY,
        NONCE_BYTES,
        previous_refresh_token_enc=b"previous",
    )

    assert (
        decrypt_idp_refresh_token(SECRET_ENC_KEY, idp_session)
        == "rotated-refresh-token"
    )
