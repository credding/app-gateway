from datetime import datetime, timedelta
from typing import NamedTuple, assert_never

from fastapi import Response

from app_gateway.auth_server.grants.common import (
    RedeemSessionGrantResult,
    RestoreSessionGrantResult,
    TokenGrantResult,
    TokenReplayResult,
    narrow_request_scope,
    token_error_response,
)
from app_gateway.auth_server.policy_manager import AppIdpIdentityProvider
from app_gateway.oauth import (
    GrantType,
    RefreshTokenTokenRequest,
    TokenError,
)
from app_gateway.policy import (
    Client,
    ConfidentialClient,
    IdentityProvider,
    PublicClient,
    decrypt_app_idp_client_secret,
)
from app_gateway.session import IdpSession, Session, decrypt_idp_refresh_token
from app_gateway.session.schema import RefreshTokenSessionGrant


def _is_session_grant_valid(
    session_grant: RefreshTokenSessionGrant,
    session: Session,
    client: Client,
    time: datetime,
    session_lifetime: timedelta,
    refresh_token_lifetime: timedelta,
) -> bool:
    return (
        session.client_id == client.client_id
        and session.revoked_at is None
        and time - session.issued_at < session_lifetime
        and time - session_grant.issued_at < refresh_token_lifetime
    )


def check_refresh_token_grant(
    maybe_restored: RestoreSessionGrantResult[RefreshTokenSessionGrant] | None,
    client: Client,
    time: datetime,
    session_lifetime: timedelta,
    refresh_token_lifetime: timedelta,
) -> RestoreSessionGrantResult[RefreshTokenSessionGrant] | TokenReplayResult | Response:
    match maybe_restored:
        case RestoreSessionGrantResult(session_grant, session, _) as restored:
            pass
        case None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    if not _is_session_grant_valid(
        session_grant,
        session,
        client,
        time,
        session_lifetime,
        refresh_token_lifetime,
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    if session_grant.invalidated_at is not None:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return restored


def parse_refresh_token_grant(
    maybe_redeemed: RedeemSessionGrantResult[RefreshTokenSessionGrant] | None,
    client: Client,
    request: RefreshTokenTokenRequest,
    time: datetime,
    session_lifetime: timedelta,
    refresh_token_lifetime: timedelta,
) -> TokenGrantResult | TokenReplayResult | Response:
    match maybe_redeemed:
        case RedeemSessionGrantResult(session_grant, session, replayed):
            pass
        case None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    if not _is_session_grant_valid(
        session_grant,
        session,
        client,
        time,
        session_lifetime,
        refresh_token_lifetime,
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return narrow_request_scope(session, client, request, None)


class SessionEndedResult(NamedTuple):
    session_id: str
    response: Response


class IdpSessionValid(NamedTuple):
    pass


class IdpSessionRefresh(NamedTuple):
    idp_session: IdpSession


def check_idp_session(
    maybe_idp_session: IdpSession | None,
    session: Session,
    time: datetime,
) -> IdpSessionValid | IdpSessionRefresh | SessionEndedResult:
    match maybe_idp_session:
        case IdpSession(expires_in=None):
            return IdpSessionValid()
        case IdpSession(issued_at=issued_at, expires_in=timedelta() as expires_in) if (
            time < issued_at + expires_in
        ):
            return IdpSessionValid()
        case IdpSession(refresh_token_enc=bytes()) as idp_session:
            return IdpSessionRefresh(idp_session)
        case IdpSession() | None:
            return idp_session_ended(session)
        case unreachable:
            assert_never(unreachable)


class IdpRefreshTokenRequestResult(NamedTuple):
    idp: IdentityProvider
    request: RefreshTokenTokenRequest


def create_idp_refresh_token_request(
    maybe_app_idp: AppIdpIdentityProvider | None,
    idp_session: IdpSession,
    session: Session,
    secret_enc_key: bytes,
) -> IdpRefreshTokenRequestResult | SessionEndedResult:
    match maybe_app_idp:
        case AppIdpIdentityProvider(app_idp, idp):
            pass
        case None:
            return idp_session_ended(session)
        case unreachable:
            assert_never(unreachable)

    refresh_token = decrypt_idp_refresh_token(secret_enc_key, idp_session)
    if refresh_token is None:
        return idp_session_ended(session)

    return IdpRefreshTokenRequestResult(
        idp,
        RefreshTokenTokenRequest(
            client_id=app_idp.client_id,
            client_secret=decrypt_app_idp_client_secret(secret_enc_key, app_idp),
            grant_type=GrantType.REFRESH_TOKEN,
            refresh_token=refresh_token,
        ),
    )


def idp_session_ended(session: Session) -> SessionEndedResult:
    return SessionEndedResult(
        session.session_id,
        token_error_response(TokenError.INVALID_GRANT),
    )


def refresh_session_expires_at(
    client: Client,
    time: datetime,
    confidential_client_refresh_token_lifetime: timedelta,
) -> datetime | None:
    match client:
        case ConfidentialClient():
            return time + confidential_client_refresh_token_lifetime
        case PublicClient():
            return None
        case unreachable:
            assert_never(unreachable)
