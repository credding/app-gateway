from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from fastapi import Response

from app_gateway.auth_server.grants.common import TokenGrantResult, TokenReplayResult
from app_gateway.auth_server.grants.device_code import (
    check_device_authorization,
    parse_device_code_grant,
)
from app_gateway.auth_server.session_manager import RedeemSessionGrantResult
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import DeviceCodeTokenRequest, GrantType
from app_gateway.policy import AccessType, ConfidentialClient, PublicClient
from app_gateway.session import AuthorizationScope, DeviceAuthorization, Session
from app_gateway.session.schema import (
    DeviceCodeSessionGrant,
    SessionGrantType,
    SessionState,
)
from tests.auth_server.constants import (
    CLIENT_ID,
    RESOURCE,
    SCOPE,
    SESSION_ID,
    TIME,
)
from tests.auth_server.helpers import error_body

DEVICE_CODE = "device-code"
DEVICE_CODE_LIFETIME = timedelta(minutes=10)
SESSION_LIFETIME = timedelta(days=30)
VALID_TIME = TIME + timedelta(minutes=1)


@pytest.fixture
def device_auth() -> DeviceAuthorization:
    return DeviceAuthorization(
        device_code_hash=hash_token(DEVICE_CODE),
        user_code_hash=hash_token("BCDFGHJK"),
        client_id=CLIENT_ID,
        request_scope=AuthorizationScope(resource=RESOURCE, scope=SCOPE),
        issued_at=TIME,
    )


@pytest.fixture
def device_code_grant() -> DeviceCodeSessionGrant:
    return DeviceCodeSessionGrant(
        grant_type=SessionGrantType.DEVICE_CODE,
        token_hash=hash_token(DEVICE_CODE),
        session_id=SESSION_ID,
        state=SessionState(),
        issued_at=TIME,
    )


@pytest.fixture
def device_request() -> DeviceCodeTokenRequest:
    return DeviceCodeTokenRequest(
        grant_type=GrantType.DEVICE_CODE, device_code=DEVICE_CODE
    )


def test_check_device_authorization_approved(
    device_auth: DeviceAuthorization, confidential_client: ConfidentialClient
) -> None:
    approved = device_auth.model_copy(update={"approved_at": TIME})

    assert (
        check_device_authorization(
            approved, confidential_client, VALID_TIME, DEVICE_CODE_LIFETIME
        )
        is None
    )


@pytest.mark.parametrize(
    ("update", "time", "expected_error"),
    [
        ({}, VALID_TIME, "authorization_pending"),
        ({"denied_at": TIME}, VALID_TIME, "access_denied"),
        ({}, TIME + DEVICE_CODE_LIFETIME, "expired_token"),
        ({"approved_at": TIME}, TIME + DEVICE_CODE_LIFETIME, "expired_token"),
        ({"denied_at": TIME}, TIME + DEVICE_CODE_LIFETIME, "expired_token"),
        ({"client_id": "svc_other"}, VALID_TIME, "invalid_grant"),
    ],
    ids=[
        "pending",
        "denied",
        "expired-pending",
        "expired-approved",
        "expired-denied",
        "wrong-client",
    ],
)
def test_check_device_authorization_errors(
    device_auth: DeviceAuthorization,
    confidential_client: ConfidentialClient,
    update: dict[str, object],
    time: datetime,
    expected_error: str,
) -> None:
    result = check_device_authorization(
        device_auth.model_copy(update=update),
        confidential_client,
        time,
        DEVICE_CODE_LIFETIME,
    )

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert result.headers["cache-control"] == "no-store"
    assert error_body(result)["error"] == expected_error


def test_check_device_authorization_unknown(
    confidential_client: ConfidentialClient,
) -> None:
    result = check_device_authorization(
        None, confidential_client, VALID_TIME, DEVICE_CODE_LIFETIME
    )

    assert isinstance(result, Response)
    assert error_body(result)["error"] == "invalid_grant"


def test_parse_device_code_grant(
    session: Session,
    device_code_grant: DeviceCodeSessionGrant,
    confidential_client: ConfidentialClient,
    device_request: DeviceCodeTokenRequest,
) -> None:
    result = parse_device_code_grant(
        RedeemSessionGrantResult(device_code_grant, session, replayed=False),
        confidential_client,
        device_request,
        VALID_TIME,
        SESSION_LIFETIME,
    )

    assert result == TokenGrantResult(
        session,
        AuthorizationScope(resource=RESOURCE, scope=SCOPE),
        AccessType.AUTHENTICATED,
        None,
    )


def test_parse_device_code_grant_replayed(
    session: Session,
    device_code_grant: DeviceCodeSessionGrant,
    confidential_client: ConfidentialClient,
    device_request: DeviceCodeTokenRequest,
) -> None:
    result = parse_device_code_grant(
        RedeemSessionGrantResult(device_code_grant, session, replayed=True),
        confidential_client,
        device_request,
        VALID_TIME,
        SESSION_LIFETIME,
    )

    assert isinstance(result, TokenReplayResult)
    assert result.session_id == SESSION_ID
    assert error_body(result.response)["error"] == "invalid_grant"


def test_parse_device_code_grant_not_found(
    confidential_client: ConfidentialClient,
    device_request: DeviceCodeTokenRequest,
) -> None:
    result = parse_device_code_grant(
        None, confidential_client, device_request, VALID_TIME, SESSION_LIFETIME
    )

    assert isinstance(result, Response)
    assert error_body(result)["error"] == "invalid_grant"


@pytest.mark.parametrize(
    ("session_update", "time"),
    [
        ({"revoked_at": TIME}, VALID_TIME),
        ({}, TIME + SESSION_LIFETIME),
    ],
    ids=["revoked", "session-expired"],
)
def test_parse_device_code_grant_invalid_session(
    session: Session,
    device_code_grant: DeviceCodeSessionGrant,
    confidential_client: ConfidentialClient,
    device_request: DeviceCodeTokenRequest,
    session_update: dict[str, object],
    time: datetime,
) -> None:
    result = parse_device_code_grant(
        RedeemSessionGrantResult(
            device_code_grant,
            session.model_copy(update=session_update),
            replayed=True,
        ),
        confidential_client,
        device_request,
        time,
        SESSION_LIFETIME,
    )

    assert isinstance(result, Response)
    assert error_body(result)["error"] == "invalid_grant"


def test_parse_device_code_grant_wrong_client(
    session: Session,
    device_code_grant: DeviceCodeSessionGrant,
    public_client: PublicClient,
    device_request: DeviceCodeTokenRequest,
) -> None:
    result = parse_device_code_grant(
        RedeemSessionGrantResult(device_code_grant, session, replayed=False),
        public_client,
        device_request,
        VALID_TIME,
        SESSION_LIFETIME,
    )

    assert isinstance(result, Response)
    assert error_body(result)["error"] == "invalid_grant"
