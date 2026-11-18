from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from fastapi import Response

from app_gateway.auth_server.grants.authorization_code import (
    parse_authorization_code_grant,
)
from app_gateway.auth_server.grants.common import TokenGrantResult, TokenReplayResult
from app_gateway.auth_server.session_manager import RedeemSessionGrantResult
from app_gateway.oauth import AuthorizationCodeTokenRequest, GrantType
from app_gateway.policy import AccessType, ConfidentialClient
from app_gateway.session import AuthorizationScope, Session
from app_gateway.session.schema import AuthorizationCodeSessionGrant
from tests.auth_server.constants import (
    REDIRECT_URI,
    REQUEST_NONCE,
    RESOURCE,
    SCOPE,
    SESSION_ID,
    TIME,
)
from tests.auth_server.helpers import error_body

SESSION_LIFETIME = timedelta(days=30)
AUTHORIZATION_CODE_LIFETIME = timedelta(minutes=5)


@pytest.mark.parametrize(
    ("request_kwargs", "expected_scope"),
    [
        ({"redirect_uri": REDIRECT_URI}, SCOPE),
        ({}, SCOPE),
        ({"redirect_uri": REDIRECT_URI, "scope": "openid"}, "openid"),
    ],
    ids=["with-redirect-uri", "without-redirect-uri", "narrowed-scope"],
)
def test_parse_authorization_code_grant(
    session: Session,
    authorization_code_grant: AuthorizationCodeSessionGrant,
    confidential_client: ConfidentialClient,
    authorization_code: str,
    code_verifier: str,
    request_kwargs: dict[str, str],
    expected_scope: str,
) -> None:
    request = AuthorizationCodeTokenRequest(
        grant_type=GrantType.AUTHORIZATION_CODE,
        code=authorization_code,
        code_verifier=code_verifier,
        **request_kwargs,
    )

    result = parse_authorization_code_grant(
        RedeemSessionGrantResult(authorization_code_grant, session, replayed=False),
        confidential_client,
        request,
        TIME + AUTHORIZATION_CODE_LIFETIME - timedelta(seconds=1),
        SESSION_LIFETIME,
        AUTHORIZATION_CODE_LIFETIME,
    )

    assert result == TokenGrantResult(
        session,
        AuthorizationScope(resource=RESOURCE, scope=expected_scope),
        AccessType.AUTHENTICATED,
        REQUEST_NONCE,
    )


VALID_TIME = TIME + timedelta(minutes=1)


@pytest.fixture
def code_request(
    authorization_code: str, code_verifier: str
) -> AuthorizationCodeTokenRequest:
    return AuthorizationCodeTokenRequest(
        grant_type=GrantType.AUTHORIZATION_CODE,
        code=authorization_code,
        code_verifier=code_verifier,
        redirect_uri=REDIRECT_URI,
    )


def _parse(
    session: Session,
    grant: AuthorizationCodeSessionGrant,
    client: ConfidentialClient,
    request: AuthorizationCodeTokenRequest,
    time: datetime = VALID_TIME,
    *,
    replayed: bool = False,
) -> TokenGrantResult | TokenReplayResult | Response:
    return parse_authorization_code_grant(
        RedeemSessionGrantResult(grant, session, replayed=replayed),
        client,
        request,
        time,
        SESSION_LIFETIME,
        AUTHORIZATION_CODE_LIFETIME,
    )


def test_parse_authorization_code_grant_not_found(
    confidential_client: ConfidentialClient,
    code_request: AuthorizationCodeTokenRequest,
) -> None:
    result = parse_authorization_code_grant(
        None,
        confidential_client,
        code_request,
        VALID_TIME,
        SESSION_LIFETIME,
        AUTHORIZATION_CODE_LIFETIME,
    )

    assert isinstance(result, Response)
    assert error_body(result) == {"error": "invalid_grant"}


@pytest.mark.parametrize("replayed", [False, True])
@pytest.mark.parametrize(
    ("session_update", "request_update", "time"),
    [
        ({"client_id": "svc_other"}, {}, VALID_TIME),
        ({"revoked_at": TIME}, {}, VALID_TIME),
        ({"issued_at": VALID_TIME - SESSION_LIFETIME}, {}, VALID_TIME),
        ({}, {}, TIME + AUTHORIZATION_CODE_LIFETIME),
        ({}, {"redirect_uri": "https://app.example.test/other"}, VALID_TIME),
        ({}, {"code_verifier": "x" * 43}, VALID_TIME),
    ],
    ids=[
        "client-mismatch",
        "session-revoked",
        "session-expired",
        "code-expired",
        "redirect-uri-mismatch",
        "pkce-mismatch",
    ],
)
def test_parse_authorization_code_grant_invalid(
    session: Session,
    authorization_code_grant: AuthorizationCodeSessionGrant,
    confidential_client: ConfidentialClient,
    code_request: AuthorizationCodeTokenRequest,
    session_update: dict[str, object],
    request_update: dict[str, str],
    time: datetime,
    *,
    replayed: bool,
) -> None:
    result = _parse(
        session.model_copy(update=session_update),
        authorization_code_grant,
        confidential_client,
        code_request.model_copy(update=request_update),
        time,
        replayed=replayed,
    )

    # Validation runs before replay detection: an invalid request for a
    # replayed code is a plain error, not a TokenReplayResult.
    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result) == {"error": "invalid_grant"}


def test_parse_authorization_code_grant_replayed(
    session: Session,
    authorization_code_grant: AuthorizationCodeSessionGrant,
    confidential_client: ConfidentialClient,
    code_request: AuthorizationCodeTokenRequest,
) -> None:
    result = _parse(
        session,
        authorization_code_grant,
        confidential_client,
        code_request,
        replayed=True,
    )

    assert isinstance(result, TokenReplayResult)
    assert result.session_id == SESSION_ID
    assert error_body(result.response) == {"error": "invalid_grant"}


def test_parse_authorization_code_grant_scope_widened(
    session: Session,
    authorization_code_grant: AuthorizationCodeSessionGrant,
    confidential_client: ConfidentialClient,
    code_request: AuthorizationCodeTokenRequest,
) -> None:
    result = _parse(
        session,
        authorization_code_grant,
        confidential_client,
        code_request.model_copy(update={"scope": f"{SCOPE} offline_access"}),
    )

    assert isinstance(result, Response)
    assert error_body(result) == {"error": "invalid_scope"}
