from datetime import datetime, timedelta
from typing import assert_never

from fastapi import Response

from app_gateway.auth_server.grants.common import (
    TokenGrantResult,
    TokenReplayResult,
    narrow_request_scope,
    token_error_response,
)
from app_gateway.auth_server.session_manager import RedeemSessionGrantResult
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    TokenError,
    verify_code_challenge,
)
from app_gateway.policy import Client
from app_gateway.session.schema import AuthorizationCodeSessionGrant


def parse_authorization_code_grant(
    maybe_redeemed: RedeemSessionGrantResult[AuthorizationCodeSessionGrant] | None,
    client: Client,
    request: AuthorizationCodeTokenRequest,
    time: datetime,
    session_lifetime: timedelta,
    authorization_code_lifetime: timedelta,
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
        or time - session_grant.issued_at >= authorization_code_lifetime
        or (
            request.redirect_uri is not None
            and request.redirect_uri != session_grant.state.redirect_uri
        )
        or not verify_code_challenge(
            request.code_verifier, session_grant.state.code_challenge
        )
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return narrow_request_scope(session, client, request, session_grant.state.nonce)
