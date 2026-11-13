from datetime import datetime, timedelta
from typing import assert_never

from fastapi import Response

from app_gateway.auth_server.token import (
    RedeemSessionGrantResult,
    TokenGrantResult,
    TokenReplayResult,
    narrow_request_scope,
    token_error_response,
)
from app_gateway.oauth import RefreshTokenTokenRequest, TokenError
from app_gateway.policy import Client, ConfidentialClient, PublicClient


def parse_refresh_token_grant(
    maybe_redeemed: RedeemSessionGrantResult | None,
    client: Client,
    request: RefreshTokenTokenRequest,
    time: datetime,
) -> TokenGrantResult | TokenReplayResult | Response:
    match maybe_redeemed:
        case RedeemSessionGrantResult(_, session, replayed):
            pass
        case None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    # The session's expiry bounds every refresh grant issued against it.
    if (
        session.client_id != client.client_id
        or session.revoked_at is not None
        or time >= session.expires_at
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    # Refresh tokens rotate on every use, so a replayed token indicates it
    # leaked; revoke the whole session (RFC 9700 Section 4.14.2).
    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    # RFC 6749 Section 6: scope may only narrow relative to the original grant.
    return narrow_request_scope(session, client, request)


def refresh_session_expires_at(
    client: Client,
    time: datetime,
    lifetime: timedelta,
) -> datetime | None:
    match client:
        case ConfidentialClient():
            return time + lifetime
        case PublicClient():
            return None
        case unreachable:
            assert_never(unreachable)
