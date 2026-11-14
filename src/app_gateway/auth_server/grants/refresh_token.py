from datetime import datetime, timedelta
from typing import assert_never

from fastapi import Response

from app_gateway.auth_server.grants.common import (
    RedeemSessionGrantResult,
    TokenGrantResult,
    TokenReplayResult,
    narrow_request_scope,
    token_error_response,
)
from app_gateway.oauth import RefreshTokenTokenRequest, TokenError
from app_gateway.policy import Client, ConfidentialClient, PublicClient
from app_gateway.session.schema import RefreshTokenSessionGrant


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

    if (
        session.client_id != client.client_id
        or session.revoked_at is not None
        or time - session.issued_at >= session_lifetime
        or time - session_grant.issued_at >= refresh_token_lifetime
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return narrow_request_scope(session, client, request)


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
