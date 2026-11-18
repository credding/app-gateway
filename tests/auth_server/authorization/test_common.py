from datetime import timedelta
from http import HTTPStatus

from fastapi import Response

from app_gateway.auth_server.authorization.common import (
    parse_idp_authorization_callback_response,
)
from app_gateway.auth_server.authorization.device_authorization import (
    ParseDeviceCallbackResponseResult,
)
from app_gateway.auth_server.authorization.idp_authentication import (
    ParseAuthorizationCallbackResponseResult,
)
from app_gateway.session import DeviceIdpAuthorizationState, IdpAuthorizationState
from tests.auth_server.constants import ISSUER, TIME
from tests.auth_server.helpers import error_body

STATE_LIFETIME = timedelta(minutes=5)


def test_parse_idp_authorization_callback_response_device_state(
    device_idp_authorization_state: DeviceIdpAuthorizationState,
) -> None:
    result = parse_idp_authorization_callback_response(
        device_idp_authorization_state,
        {"code": "idp-code"},
        TIME,
        ISSUER,
        STATE_LIFETIME,
    )

    assert result == ParseDeviceCallbackResponseResult(
        device_idp_authorization_state, "idp-code"
    )


def test_parse_idp_authorization_callback_response_authorization_code_state(
    idp_authorization_state: IdpAuthorizationState,
) -> None:
    result = parse_idp_authorization_callback_response(
        idp_authorization_state, {"code": "idp-code"}, TIME, ISSUER, STATE_LIFETIME
    )

    assert result == ParseAuthorizationCallbackResponseResult(
        idp_authorization_state, "idp-code"
    )


def test_parse_idp_authorization_callback_response_missing_state() -> None:
    result = parse_idp_authorization_callback_response(
        None, {"code": "idp-code"}, TIME, ISSUER, STATE_LIFETIME
    )

    assert isinstance(result, Response)
    assert result.status_code == HTTPStatus.BAD_REQUEST
    assert error_body(result)["error"] == "invalid_request"
