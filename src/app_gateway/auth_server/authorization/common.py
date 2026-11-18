from datetime import datetime, timedelta
from typing import assert_never

from fastapi import Response

from app_gateway.auth_server.authorization.device_authorization import (
    DeviceCallbackDenied,
    DevicePage,
    ParseDeviceCallbackResponseResult,
    parse_device_callback_response,
)
from app_gateway.auth_server.authorization.idp_authentication import (
    ParseAuthorizationCallbackResponseResult,
    parse_authorization_callback_response,
)
from app_gateway.common.validation import FormParams
from app_gateway.session import (
    AnyIdpAuthorizationState,
    DeviceIdpAuthorizationState,
    IdpAuthorizationState,
)


def parse_idp_authorization_callback_response(
    maybe_state: AnyIdpAuthorizationState | None,
    params: FormParams,
    time: datetime,
    issuer: str,
    state_lifetime: timedelta,
) -> (
    ParseAuthorizationCallbackResponseResult
    | ParseDeviceCallbackResponseResult
    | DeviceCallbackDenied
    | DevicePage
    | Response
):
    match maybe_state:
        case DeviceIdpAuthorizationState() as state:
            return parse_device_callback_response(state, params, time, state_lifetime)
        case IdpAuthorizationState() | None:
            return parse_authorization_callback_response(
                maybe_state, params, time, issuer, state_lifetime
            )
        case unreachable:
            assert_never(unreachable)
