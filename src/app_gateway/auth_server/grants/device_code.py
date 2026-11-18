from datetime import datetime, timedelta
from typing import assert_never

from fastapi import Response

from app_gateway.auth_server.authorization.device_authorization import (
    is_device_authorization_expired,
)
from app_gateway.auth_server.grants.common import (
    TokenGrantResult,
    TokenReplayResult,
    narrow_request_scope,
    token_error_response,
)
from app_gateway.auth_server.session_manager import RedeemSessionGrantResult
from app_gateway.oauth import DeviceCodeTokenRequest, TokenError
from app_gateway.policy import Client
from app_gateway.session import DeviceAuthorization
from app_gateway.session.schema import DeviceCodeSessionGrant


def check_device_authorization(
    maybe_device_auth: DeviceAuthorization | None,
    client: Client,
    time: datetime,
    device_code_lifetime: timedelta,
) -> Response | None:
    # RFC 8628 Section 3.5.
    match maybe_device_auth:
        case DeviceAuthorization() as device_auth if (
            device_auth.client_id == client.client_id
        ):
            pass
        case DeviceAuthorization() | None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    if is_device_authorization_expired(device_auth, time, device_code_lifetime):
        return token_error_response(TokenError.EXPIRED_TOKEN)
    if device_auth.denied_at is not None:
        return token_error_response(TokenError.ACCESS_DENIED)
    if device_auth.approved_at is None:
        return token_error_response(TokenError.AUTHORIZATION_PENDING)
    return None


def parse_device_code_grant(
    maybe_redeemed: RedeemSessionGrantResult[DeviceCodeSessionGrant] | None,
    client: Client,
    request: DeviceCodeTokenRequest,
    time: datetime,
    session_lifetime: timedelta,
) -> TokenGrantResult | TokenReplayResult | Response:
    match maybe_redeemed:
        case RedeemSessionGrantResult(_, session, replayed):
            pass
        case None:
            return token_error_response(TokenError.INVALID_GRANT)
        case unreachable:
            assert_never(unreachable)

    if (
        session.client_id != client.client_id
        or session.revoked_at is not None
        or time - session.issued_at >= session_lifetime
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    if replayed:
        return TokenReplayResult(
            session.session_id,
            token_error_response(TokenError.INVALID_GRANT),
        )

    return narrow_request_scope(session, client, request, None)
