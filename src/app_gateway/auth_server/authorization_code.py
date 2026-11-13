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
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    TokenError,
    verify_code_challenge,
)
from app_gateway.policy import Client


def parse_authorization_code_grant(
    maybe_redeemed: RedeemSessionGrantResult | None,
    client: Client,
    request: AuthorizationCodeTokenRequest,
    time: datetime,
    code_lifetime: timedelta,
) -> TokenGrantResult | TokenReplayResult | Response:
    match maybe_redeemed:
        case RedeemSessionGrantResult(session_grant, session, replayed):
            pass
        case None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    request_state = session_grant.request_state

    if (
        session.client_id != client.client_id
        or time - session_grant.issued_at > code_lifetime
        or session.revoked_at is not None
        or time >= session.expires_at
        or request_state is None
        or (
            request.redirect_uri is not None
            and request.redirect_uri != request_state.redirect_uri
        )
        or not verify_code_challenge(
            request.code_verifier, request_state.code_challenge
        )
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    # Only revoke once the caller has proven possession of the client
    # credentials and PKCE verifier, so a leaked code alone can't revoke.
    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return narrow_request_scope(session, client, request)
