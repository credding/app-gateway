from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from fastapi import Response

from app_gateway.auth_server.grants.common import TokenGrantResult, TokenReplayResult
from app_gateway.auth_server.grants.refresh_token import (
    IdpRefreshTokenRequestResult,
    IdpSessionRefresh,
    IdpSessionValid,
    SessionEndedResult,
    check_idp_session,
    check_refresh_token_grant,
    create_idp_refresh_token_request,
    parse_refresh_token_grant,
    refresh_session_expires_at,
)
from app_gateway.auth_server.policy_manager import AppIdpIdentityProvider
from app_gateway.auth_server.session_manager import (
    RedeemSessionGrantResult,
    RestoreSessionGrantResult,
)
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import GrantType, RefreshTokenTokenRequest
from app_gateway.policy import (
    AccessType,
    ConfidentialClient,
    IdentityProvider,
    PublicClient,
)
from app_gateway.session import (
    AuthorizationScope,
    IdpSession,
    Session,
    encrypt_idp_refresh_token,
)
from app_gateway.session.schema import (
    RefreshTokenSessionGrant,
    SessionGrantType,
    SessionState,
)
from tests.auth_server.constants import (
    CLIENT_ID,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_ISSUER,
    NONCE_BYTES,
    RESOURCE,
    SCOPE,
    SECRET_ENC_KEY,
    SESSION_ID,
    TIME,
    USER_ID,
)
from tests.auth_server.helpers import error_body

SESSION_LIFETIME = timedelta(days=30)
REFRESH_TOKEN_LIFETIME = timedelta(days=7)
IDP_REFRESH_TOKEN = "idp-refresh-token"
# Later than the session start, but within both lifetimes.
REFRESH_TIME = TIME + timedelta(days=1)


@pytest.fixture
def refresh_token_grant() -> RefreshTokenSessionGrant:
    return RefreshTokenSessionGrant(
        grant_type=SessionGrantType.REFRESH_TOKEN,
        token_hash=hash_token("refresh-token"),
        session_id=SESSION_ID,
        state=SessionState(),
        issued_at=TIME + timedelta(hours=12),
    )


@pytest.fixture
def idp_session() -> IdpSession:
    return IdpSession(
        client_id=CLIENT_ID,
        user_id=USER_ID,
        idp_issuer=IDP_ISSUER,
        expires_in=timedelta(hours=1),
        refresh_token_enc=encrypt_idp_refresh_token(
            SECRET_ENC_KEY,
            NONCE_BYTES,
            CLIENT_ID,
            USER_ID,
            IDP_ISSUER,
            IDP_REFRESH_TOKEN,
        ),
        issued_at=REFRESH_TIME - timedelta(minutes=30),
    )


def _refresh_request(**kwargs: str) -> RefreshTokenTokenRequest:
    return RefreshTokenTokenRequest(
        grant_type=GrantType.REFRESH_TOKEN, refresh_token="refresh-token", **kwargs
    )


@pytest.mark.parametrize("with_idp_session", [True, False])
def test_check_refresh_token_grant(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    idp_session: IdpSession,
    confidential_client: ConfidentialClient,
    *,
    with_idp_session: bool,
) -> None:
    restored = RestoreSessionGrantResult(
        refresh_token_grant, session, idp_session if with_idp_session else None
    )

    result = check_refresh_token_grant(
        restored,
        confidential_client,
        REFRESH_TIME,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    assert result is restored


@pytest.mark.parametrize(
    ("request_kwargs", "expected_scope"),
    [
        ({}, SCOPE),
        ({"scope": "openid email"}, "openid email"),
        ({"resource": RESOURCE}, SCOPE),
    ],
    ids=["inherit", "narrowed-scope", "same-resource"],
)
def test_parse_refresh_token_grant(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
    request_kwargs: dict[str, str],
    expected_scope: str,
) -> None:
    result = parse_refresh_token_grant(
        RedeemSessionGrantResult(refresh_token_grant, session, replayed=False),
        confidential_client,
        _refresh_request(**request_kwargs),
        REFRESH_TIME,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    # Refreshed ID tokens never carry the original authorization nonce.
    assert result == TokenGrantResult(
        session,
        AuthorizationScope(resource=RESOURCE, scope=expected_scope),
        AccessType.AUTHENTICATED,
        None,
    )


def test_parse_refresh_token_grant_public_client(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    public_client: PublicClient,
) -> None:
    # Public clients get short (8h) session lifetimes, so refresh within them.
    public_session = session.model_copy(update={"client_id": public_client.client_id})
    grant = refresh_token_grant.model_copy(
        update={"issued_at": TIME + timedelta(hours=1)}
    )

    result = parse_refresh_token_grant(
        RedeemSessionGrantResult(grant, public_session, replayed=False),
        public_client,
        _refresh_request(),
        TIME + timedelta(hours=2),
        timedelta(hours=8),
        timedelta(hours=8),
    )

    assert isinstance(result, TokenGrantResult)
    assert result.access_type is AccessType.PUBLIC


def test_check_idp_session_within_expiry(
    idp_session: IdpSession, session: Session
) -> None:
    assert check_idp_session(idp_session, session, REFRESH_TIME) == IdpSessionValid()


def test_check_idp_session_without_expiry(
    idp_session: IdpSession, session: Session
) -> None:
    non_expiring = idp_session.model_copy(
        update={"expires_in": None, "refresh_token_enc": None}
    )

    result = check_idp_session(non_expiring, session, REFRESH_TIME + SESSION_LIFETIME)

    assert result == IdpSessionValid()


def test_check_idp_session_needs_refresh(
    idp_session: IdpSession, session: Session
) -> None:
    expired_at = idp_session.issued_at + timedelta(hours=1)

    result = check_idp_session(idp_session, session, expired_at)

    assert result == IdpSessionRefresh(idp_session)


def test_create_idp_refresh_token_request(
    app_idp_idp: AppIdpIdentityProvider,
    idp: IdentityProvider,
    idp_session: IdpSession,
    session: Session,
) -> None:
    result = create_idp_refresh_token_request(
        app_idp_idp, idp_session, session, SECRET_ENC_KEY
    )

    assert result == IdpRefreshTokenRequestResult(
        idp,
        RefreshTokenTokenRequest(
            grant_type=GrantType.REFRESH_TOKEN,
            client_id=IDP_CLIENT_ID,
            client_secret=IDP_CLIENT_SECRET,
            refresh_token=IDP_REFRESH_TOKEN,
        ),
    )


def test_refresh_session_expires_at_confidential_client(
    confidential_client: ConfidentialClient,
) -> None:
    result = refresh_session_expires_at(
        confidential_client, TIME, REFRESH_TOKEN_LIFETIME
    )

    assert result == TIME + REFRESH_TOKEN_LIFETIME


def test_refresh_session_expires_at_public_client(
    public_client: PublicClient,
) -> None:
    assert (
        refresh_session_expires_at(public_client, TIME, REFRESH_TOKEN_LIFETIME) is None
    )


# Each mutation makes _is_session_grant_valid false; ids name the failed check.
_INVALID_GRANT_CASES = pytest.mark.parametrize(
    ("session_update", "grant_update", "time"),
    [
        ({"client_id": "svc_other"}, {}, REFRESH_TIME),
        ({"revoked_at": TIME}, {}, REFRESH_TIME),
        ({}, {}, TIME + SESSION_LIFETIME),
        ({}, {"issued_at": REFRESH_TIME - REFRESH_TOKEN_LIFETIME}, REFRESH_TIME),
    ],
    ids=["client-mismatch", "session-revoked", "session-expired", "grant-expired"],
)


def _assert_invalid_grant(result: object) -> None:
    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result) == {"error": "invalid_grant"}


def test_check_refresh_token_grant_not_found(
    confidential_client: ConfidentialClient,
) -> None:
    _assert_invalid_grant(
        check_refresh_token_grant(
            None,
            confidential_client,
            REFRESH_TIME,
            SESSION_LIFETIME,
            REFRESH_TOKEN_LIFETIME,
        )
    )


@pytest.mark.parametrize("invalidated", [False, True])
@_INVALID_GRANT_CASES
def test_check_refresh_token_grant_invalid(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
    session_update: dict[str, object],
    grant_update: dict[str, object],
    time: datetime,
    *,
    invalidated: bool,
) -> None:
    grant = refresh_token_grant.model_copy(
        update=grant_update | ({"invalidated_at": TIME} if invalidated else {})
    )

    result = check_refresh_token_grant(
        RestoreSessionGrantResult(
            grant, session.model_copy(update=session_update), None
        ),
        confidential_client,
        time,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    # Validation runs before replay detection.
    _assert_invalid_grant(result)


def test_check_refresh_token_grant_invalidated(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    grant = refresh_token_grant.model_copy(update={"invalidated_at": REFRESH_TIME})

    result = check_refresh_token_grant(
        RestoreSessionGrantResult(grant, session, None),
        confidential_client,
        REFRESH_TIME,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    assert isinstance(result, TokenReplayResult)
    assert result.session_id == SESSION_ID
    _assert_invalid_grant(result.response)


def test_parse_refresh_token_grant_not_found(
    confidential_client: ConfidentialClient,
) -> None:
    _assert_invalid_grant(
        parse_refresh_token_grant(
            None,
            confidential_client,
            _refresh_request(),
            REFRESH_TIME,
            SESSION_LIFETIME,
            REFRESH_TOKEN_LIFETIME,
        )
    )


@pytest.mark.parametrize("replayed", [False, True])
@_INVALID_GRANT_CASES
def test_parse_refresh_token_grant_invalid(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
    session_update: dict[str, object],
    grant_update: dict[str, object],
    time: datetime,
    *,
    replayed: bool,
) -> None:
    result = parse_refresh_token_grant(
        RedeemSessionGrantResult(
            refresh_token_grant.model_copy(update=grant_update),
            session.model_copy(update=session_update),
            replayed=replayed,
        ),
        confidential_client,
        _refresh_request(),
        time,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    _assert_invalid_grant(result)


def test_parse_refresh_token_grant_replayed(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
) -> None:
    result = parse_refresh_token_grant(
        RedeemSessionGrantResult(refresh_token_grant, session, replayed=True),
        confidential_client,
        _refresh_request(),
        REFRESH_TIME,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    assert isinstance(result, TokenReplayResult)
    assert result.session_id == SESSION_ID
    _assert_invalid_grant(result.response)


@pytest.mark.parametrize(
    ("request_kwargs", "expected_error"),
    [
        ({"scope": f"{SCOPE} offline_access"}, "invalid_scope"),
        ({"resource": "https://other.example.test"}, "invalid_target"),
    ],
    ids=["scope-widened", "resource-mismatch"],
)
def test_parse_refresh_token_grant_scope_errors(
    refresh_token_grant: RefreshTokenSessionGrant,
    session: Session,
    confidential_client: ConfidentialClient,
    request_kwargs: dict[str, str],
    expected_error: str,
) -> None:
    result = parse_refresh_token_grant(
        RedeemSessionGrantResult(refresh_token_grant, session, replayed=False),
        confidential_client,
        _refresh_request(**request_kwargs),
        REFRESH_TIME,
        SESSION_LIFETIME,
        REFRESH_TOKEN_LIFETIME,
    )

    assert isinstance(result, Response)
    assert error_body(result) == {"error": expected_error}


def _assert_session_ended(result: object) -> None:
    assert isinstance(result, SessionEndedResult)
    assert result.session_id == SESSION_ID
    _assert_invalid_grant(result.response)


def test_check_idp_session_missing(session: Session) -> None:
    _assert_session_ended(check_idp_session(None, session, REFRESH_TIME))


def test_check_idp_session_expired_without_refresh_token(
    idp_session: IdpSession, session: Session
) -> None:
    expired = idp_session.model_copy(update={"refresh_token_enc": None})

    result = check_idp_session(expired, session, REFRESH_TIME + timedelta(hours=1))

    _assert_session_ended(result)


def test_check_idp_session_without_expiry_with_refresh_token(
    idp_session: IdpSession, session: Session
) -> None:
    non_expiring = idp_session.model_copy(update={"expires_in": None})

    result = check_idp_session(non_expiring, session, REFRESH_TIME + SESSION_LIFETIME)

    assert result == IdpSessionValid()


def test_create_idp_refresh_token_request_app_idp_missing(
    idp_session: IdpSession, session: Session
) -> None:
    _assert_session_ended(
        create_idp_refresh_token_request(None, idp_session, session, SECRET_ENC_KEY)
    )


@pytest.mark.parametrize(
    ("idp_session_update", "key"),
    [
        ({"refresh_token_enc": None}, SECRET_ENC_KEY),
        ({}, bytes(32)),
        ({"user_id": "user_other"}, SECRET_ENC_KEY),
        ({"refresh_token_enc": NONCE_BYTES + b"\x00" * 32}, SECRET_ENC_KEY),
    ],
    ids=["no-refresh-token", "wrong-key", "associated-data-mismatch", "tampered"],
)
def test_create_idp_refresh_token_request_undecryptable(
    app_idp_idp: AppIdpIdentityProvider,
    idp_session: IdpSession,
    session: Session,
    idp_session_update: dict[str, object],
    key: bytes,
) -> None:
    result = create_idp_refresh_token_request(
        app_idp_idp,
        idp_session.model_copy(update=idp_session_update),
        session,
        key,
    )

    _assert_session_ended(result)
