import base64
import json
from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from fastapi import Response

from app_gateway.auth_server.authorization.device_authorization import (
    CheckDeviceVerificationResult,
    CreateDeviceAuthorizationResult,
    DeviceCallbackDenied,
    DevicePage,
    ParseDeviceAuthorizationRequestResult,
    ParseDeviceCallbackResponseResult,
    check_device_verification,
    create_device_authorization,
    create_device_idp_authorization_redirect,
    create_device_idp_token_request,
    create_device_session,
    device_approval_page,
    is_same_origin_request,
    parse_device_authorization_request,
    parse_device_callback_response,
    parse_device_verification_user_code,
)
from app_gateway.auth_server.authorization.idp_authentication import (
    AuthorizationCodeTokenRequestResult,
)
from app_gateway.auth_server.grants.common import ClientCredentials
from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
)
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    DeviceAuthorizationRequest,
    GrantType,
    compute_code_challenge,
    normalize_user_code,
)
from app_gateway.policy import AppAccessRule, ConfidentialClient, User
from app_gateway.session import (
    AuthorizationScope,
    DeviceAuthorization,
    DeviceIdpAuthorizationState,
)
from app_gateway.session.schema import SessionGrantType
from tests.auth_server.constants import (
    CALLBACK_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    DEVICE_CODE,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_ISSUER,
    ISSUER,
    RESOURCE,
    SCOPE,
    SECRET_ENC_KEY,
    SESSION_ID,
    TIME,
    USER_ID,
)
from tests.auth_server.helpers import error_body, redirect_location

USER_CODE = "BCDF-GHJK"
VERIFICATION_URI = f"{ISSUER}/oauth/device"
LIFETIME = timedelta(minutes=10)
INTERVAL = timedelta(seconds=5)
STATE_LIFETIME = timedelta(minutes=5)


@pytest.fixture
def device_auth() -> DeviceAuthorization:
    return DeviceAuthorization(
        device_code_hash=hash_token(DEVICE_CODE),
        user_code_hash=hash_token(normalize_user_code(USER_CODE)),
        client_id=CLIENT_ID,
        request_scope=AuthorizationScope(resource=RESOURCE, scope=SCOPE),
        issued_at=TIME,
    )


def test_parse_device_authorization_request_client_secret_post() -> None:
    result = parse_device_authorization_request(
        {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "scope": SCOPE},
        None,
    )

    assert result == ParseDeviceAuthorizationRequestResult(
        DeviceAuthorizationRequest(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scope=SCOPE
        ),
        ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=False),
    )


def test_parse_device_authorization_request_client_secret_basic() -> None:
    encoded = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    result = parse_device_authorization_request({}, f"Basic {encoded}")

    assert isinstance(result, ParseDeviceAuthorizationRequestResult)
    assert result.credentials == ClientCredentials(CLIENT_ID, CLIENT_SECRET, basic=True)


@pytest.mark.parametrize(
    ("params", "expected_error"),
    [
        ({}, "invalid_client"),
        ({"client_id": CLIENT_ID, "scope": ["a", "b"]}, "invalid_request"),
    ],
    ids=["missing-client", "duplicate-param"],
)
def test_parse_device_authorization_request_errors(
    params: dict[str, object], expected_error: str
) -> None:
    result = parse_device_authorization_request(params, None)

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result)["error"] == expected_error


def test_create_device_authorization(access_rule: AppAccessRule) -> None:
    request = DeviceAuthorizationRequest(
        client_id=CLIENT_ID, resource=RESOURCE, scope=SCOPE
    )

    result = create_device_authorization(
        CLIENT_ID,
        request,
        access_rule,
        DEVICE_CODE,
        USER_CODE,
        VERIFICATION_URI,
        TIME,
        LIFETIME,
        INTERVAL,
    )

    assert isinstance(result, CreateDeviceAuthorizationResult)
    assert result.device_auth == DeviceAuthorization(
        device_code_hash=hash_token(DEVICE_CODE),
        user_code_hash=hash_token("BCDFGHJK"),
        client_id=CLIENT_ID,
        request_scope=AuthorizationScope(resource=RESOURCE, scope=SCOPE),
        issued_at=TIME,
    )
    assert result.response.status_code == HTTPStatus.OK
    assert result.response.headers["cache-control"] == "no-store"
    assert json.loads(bytes(result.response.body)) == {
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": VERIFICATION_URI,
        "verification_uri_complete": f"{VERIFICATION_URI}?user_code=BCDF-GHJK",
        "expires_in": 600,
        "interval": 5,
    }


def test_create_device_authorization_unknown_resource() -> None:
    request = DeviceAuthorizationRequest(client_id=CLIENT_ID, resource=RESOURCE)

    result = create_device_authorization(
        CLIENT_ID,
        request,
        None,
        DEVICE_CODE,
        USER_CODE,
        VERIFICATION_URI,
        TIME,
        LIFETIME,
        INTERVAL,
    )

    assert isinstance(result, Response)
    assert error_body(result)["error"] == "invalid_target"


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        (ISSUER, True),
        ("https://evil.example.test", False),
        ("null", False),
        (None, False),
    ],
)
def test_is_same_origin_request(origin: str | None, expected: bool) -> None:
    assert is_same_origin_request(origin, f"{ISSUER}/") is expected


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"user_code": "bcdf-ghjk"}, "BCDFGHJK"),
        ({"user_code": " - "}, None),
        ({}, None),
    ],
)
def test_parse_device_verification_user_code(
    params: dict[str, str], expected: str | None
) -> None:
    assert parse_device_verification_user_code(params) == expected


def test_check_device_verification(
    device_auth: DeviceAuthorization,
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
) -> None:
    result = check_device_verification(
        device_auth, client_app_idps, TIME + LIFETIME - timedelta(seconds=1), LIFETIME
    )

    assert result == CheckDeviceVerificationResult(device_auth, *app_idp_idp)


@pytest.mark.parametrize(
    ("found", "time", "app_idps", "expected"),
    [
        (False, TIME, 1, DevicePage.INVALID_CODE),
        (True, TIME + LIFETIME, 1, DevicePage.INVALID_CODE),
        (True, TIME, 0, DevicePage.ERROR),
        (True, TIME, 2, DevicePage.ERROR),
    ],
    ids=["unknown-code", "expired", "no-idp", "multiple-idps"],
)
def test_check_device_verification_errors(
    device_auth: DeviceAuthorization,
    confidential_client: ConfidentialClient,
    app_idp_idp: AppIdpIdentityProvider,
    found: bool,
    time: datetime,
    app_idps: int,
    expected: DevicePage,
) -> None:
    result = check_device_verification(
        device_auth if found else None,
        ClientAppIdentityProviders(confidential_client, [app_idp_idp] * app_idps),
        time,
        LIFETIME,
    )

    assert result is expected


def test_create_device_idp_authorization_redirect(
    device_auth: DeviceAuthorization,
    app_idp_idp: AppIdpIdentityProvider,
    device_idp_authorization_state: DeviceIdpAuthorizationState,
    idp_code_verifier: str,
) -> None:
    state, response = create_device_idp_authorization_redirect(
        device_auth,
        *app_idp_idp,
        "idp-state",
        idp_code_verifier,
        CALLBACK_URL,
        TIME,
    )

    assert state == device_idp_authorization_state
    location, params = redirect_location(response)
    assert location == f"{IDP_ISSUER}/authorize"
    assert params == {
        "response_type": "code",
        "client_id": IDP_CLIENT_ID,
        "code_challenge": compute_code_challenge(idp_code_verifier),
        "code_challenge_method": "S256",
        "redirect_uri": CALLBACK_URL,
        "state": "idp-state",
    }


@pytest.mark.parametrize(
    "params",
    [{"code": "idp-code", "iss": IDP_ISSUER}, {"code": "idp-code"}],
    ids=["code-with-iss", "code"],
)
def test_parse_device_callback_response(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
    params: dict[str, str],
) -> None:
    result = parse_device_callback_response(
        device_idp_authorization_state, params, TIME, STATE_LIFETIME
    )

    assert result == ParseDeviceCallbackResponseResult(
        device_idp_authorization_state, "idp-code"
    )


def test_parse_device_callback_response_access_denied(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
) -> None:
    result = parse_device_callback_response(
        device_idp_authorization_state, {"error": "access_denied"}, TIME, STATE_LIFETIME
    )

    assert result == DeviceCallbackDenied(device_idp_authorization_state)


@pytest.mark.parametrize(
    ("params", "time"),
    [
        ({"error": "temporarily_unavailable"}, TIME),
        ({}, TIME),
        ({"code": "idp-code", "iss": "https://other"}, TIME),
        ({"code": "idp-code"}, TIME + STATE_LIFETIME),
    ],
    ids=["other-error", "no-code", "iss-mismatch", "state-expired"],
)
def test_parse_device_callback_response_errors(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
    params: dict[str, str],
    time: datetime,
) -> None:
    result = parse_device_callback_response(
        device_idp_authorization_state, params, time, STATE_LIFETIME
    )

    assert result is DevicePage.ERROR


def test_create_device_idp_token_request(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
    app_idp_idp: AppIdpIdentityProvider,
    idp_code_verifier: str,
) -> None:
    result = create_device_idp_token_request(
        app_idp_idp,
        device_idp_authorization_state,
        "idp-code",
        CALLBACK_URL,
        SECRET_ENC_KEY,
    )

    assert result == AuthorizationCodeTokenRequestResult(
        app_idp_idp.idp,
        AuthorizationCodeTokenRequest(
            client_id=IDP_CLIENT_ID,
            client_secret=IDP_CLIENT_SECRET,
            grant_type=GrantType.AUTHORIZATION_CODE,
            code="idp-code",
            code_verifier=idp_code_verifier,
            redirect_uri=CALLBACK_URL,
        ),
    )


def test_create_device_idp_token_request_missing_app_idp(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
) -> None:
    result = create_device_idp_token_request(
        None, device_idp_authorization_state, "idp-code", CALLBACK_URL, SECRET_ENC_KEY
    )

    assert result is DevicePage.ERROR


@pytest.mark.parametrize(
    ("approved", "expected"),
    [(True, DevicePage.APPROVED), (False, DevicePage.INVALID_CODE)],
)
def test_device_approval_page(approved: bool, expected: DevicePage) -> None:
    assert device_approval_page(approved) is expected


def test_create_device_session(
    device_idp_authorization_state: DeviceIdpAuthorizationState, user: User
) -> None:
    session, session_grant = create_device_session(
        device_idp_authorization_state, user, SESSION_ID, TIME
    )

    assert session.session_id == SESSION_ID
    assert session.client_id == CLIENT_ID
    assert session.user_id == USER_ID
    assert session.idp_issuer == IDP_ISSUER
    assert session.scope == AuthorizationScope(resource=RESOURCE, scope=SCOPE)
    assert session_grant.grant_type is SessionGrantType.DEVICE_CODE
    assert session_grant.token_hash == hash_token(DEVICE_CODE)
    assert session_grant.session_id == SESSION_ID
