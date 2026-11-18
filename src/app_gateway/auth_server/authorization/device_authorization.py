from datetime import datetime, timedelta
from enum import StrEnum
from typing import NamedTuple, assert_never
from urllib.parse import urlencode, urlsplit

from fastapi import Response
from pydantic import ValidationError

from app_gateway.auth_server.authorization.idp_authentication import (
    AuthorizationCodeTokenRequestResult,
    create_idp_redirect,
    create_idp_token_request,
)
from app_gateway.auth_server.grants.common import (
    ClientCredentials,
    parse_client_credentials,
    token_error_response,
)
from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
)
from app_gateway.common.clock import to_seconds
from app_gateway.common.tokens import hash_token
from app_gateway.common.validation import FormParams, parse_form_params_str
from app_gateway.oauth import (
    AuthorizationError,
    AuthorizationRequest,
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    TokenError,
    normalize_user_code,
)
from app_gateway.oauth.responses import OauthRedirectResponse, OauthResponse
from app_gateway.policy import (
    AppAccessRule,
    AppIdentityProvider,
    IdentityProvider,
    User,
)
from app_gateway.session import (
    AuthorizationScope,
    DeviceAuthorization,
    DeviceAuthorizationState,
    DeviceIdpAuthorizationState,
    Session,
)
from app_gateway.session.schema import (
    DeviceCodeSessionGrant,
    SessionGrantType,
    SessionState,
)


class DevicePage(StrEnum):
    ENTER_CODE = "enter_code"
    INVALID_CODE = "invalid_code"
    APPROVED = "approved"
    DENIED = "denied"
    ERROR = "error"


def is_device_authorization_expired(
    device_auth: DeviceAuthorization, time: datetime, lifetime: timedelta
) -> bool:
    return time - device_auth.issued_at >= lifetime


class ParseDeviceAuthorizationRequestResult(NamedTuple):
    request: DeviceAuthorizationRequest
    credentials: ClientCredentials


def parse_device_authorization_request(
    params: FormParams,
    authorization: str | None,
) -> ParseDeviceAuthorizationRequestResult | Response:
    try:
        request = DeviceAuthorizationRequest.model_validate(params)
    except ValidationError:
        return token_error_response(TokenError.INVALID_REQUEST)

    match parse_client_credentials(
        request.client_id, request.client_secret, authorization
    ):
        case ClientCredentials() as credentials:
            return ParseDeviceAuthorizationRequestResult(request, credentials)
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)


class CreateDeviceAuthorizationResult(NamedTuple):
    device_auth: DeviceAuthorization
    response: OauthResponse[DeviceAuthorizationResponse]


def create_device_authorization(
    client_id: str,
    request: DeviceAuthorizationRequest,
    maybe_access_rule: AppAccessRule | None,
    device_code: str,
    user_code: str,
    verification_uri: str,
    time: datetime,
    lifetime: timedelta,
    interval: timedelta,
) -> CreateDeviceAuthorizationResult | Response:
    if request.resource is not None and maybe_access_rule is None:
        return token_error_response(TokenError.INVALID_TARGET)

    return CreateDeviceAuthorizationResult(
        DeviceAuthorization(
            device_code_hash=hash_token(device_code),
            user_code_hash=hash_token(normalize_user_code(user_code)),
            client_id=client_id,
            request_scope=AuthorizationScope(
                resource=request.resource,
                scope=request.scope,
            ),
            issued_at=time,
        ),
        OauthResponse(
            DeviceAuthorizationResponse(
                device_code=device_code,
                user_code=user_code,
                verification_uri=verification_uri,
                verification_uri_complete=(
                    f"{verification_uri}?{urlencode({'user_code': user_code})}"
                ),
                expires_in=to_seconds(lifetime),
                interval=to_seconds(interval),
            )
        ),
    )


def is_same_origin_request(origin: str | None, issuer: str) -> bool:
    parts = urlsplit(issuer)
    return origin == f"{parts.scheme}://{parts.netloc}"


def parse_device_verification_user_code(params: FormParams) -> str | None:
    user_code = parse_form_params_str(params, "user_code")
    if user_code is None:
        return None
    return normalize_user_code(user_code) or None


class CheckDeviceVerificationResult(NamedTuple):
    device_auth: DeviceAuthorization
    app_idp: AppIdentityProvider
    idp: IdentityProvider


def check_device_verification(
    maybe_device_auth: DeviceAuthorization | None,
    maybe_client_app_idps: ClientAppIdentityProviders | None,
    time: datetime,
    lifetime: timedelta,
) -> CheckDeviceVerificationResult | DevicePage:
    if maybe_device_auth is None or is_device_authorization_expired(
        maybe_device_auth, time, lifetime
    ):
        return DevicePage.INVALID_CODE

    match maybe_client_app_idps:
        case ClientAppIdentityProviders(_, [AppIdpIdentityProvider(app_idp, idp)]):
            return CheckDeviceVerificationResult(maybe_device_auth, app_idp, idp)
        case ClientAppIdentityProviders() | None:
            return DevicePage.ERROR
        case unreachable:
            assert_never(unreachable)


class CreateDeviceIdpAuthorizationRedirectResult(NamedTuple):
    state: DeviceIdpAuthorizationState
    response: OauthRedirectResponse[AuthorizationRequest]


def create_device_idp_authorization_redirect(
    device_auth: DeviceAuthorization,
    app_idp: AppIdentityProvider,
    idp: IdentityProvider,
    idp_state: str,
    idp_code_verifier: str,
    callback_url: str,
    time: datetime,
) -> CreateDeviceIdpAuthorizationRedirectResult:
    return CreateDeviceIdpAuthorizationRedirectResult(
        DeviceIdpAuthorizationState(
            state_hash=hash_token(idp_state),
            client_id=device_auth.client_id,
            request_scope=device_auth.request_scope,
            request_state=DeviceAuthorizationState(
                device_code_hash=device_auth.device_code_hash,
            ),
            idp_slug=idp.slug,
            idp_issuer=idp.issuer,
            code_verifier=idp_code_verifier,
            issued_at=time,
        ),
        create_idp_redirect(app_idp, idp, idp_state, idp_code_verifier, callback_url),
    )


class ParseDeviceCallbackResponseResult(NamedTuple):
    state: DeviceIdpAuthorizationState
    code: str


class DeviceCallbackDenied(NamedTuple):
    state: DeviceIdpAuthorizationState


def parse_device_callback_response(
    state: DeviceIdpAuthorizationState,
    params: FormParams,
    time: datetime,
    state_lifetime: timedelta,
) -> ParseDeviceCallbackResponseResult | DeviceCallbackDenied | DevicePage:
    if time - state.issued_at >= state_lifetime:
        return DevicePage.ERROR

    maybe_iss = parse_form_params_str(params, "iss")
    if maybe_iss is not None and maybe_iss != state.idp_issuer:
        return DevicePage.ERROR

    code = parse_form_params_str(params, "code")
    if code is not None:
        return ParseDeviceCallbackResponseResult(state, code)

    match parse_form_params_str(params, "error"):
        case AuthorizationError.ACCESS_DENIED:
            return DeviceCallbackDenied(state)
        case str() | None:
            return DevicePage.ERROR
        case unreachable:
            assert_never(unreachable)


def create_device_idp_token_request(
    maybe_app_idp: AppIdpIdentityProvider | None,
    state: DeviceIdpAuthorizationState,
    code: str,
    callback_url: str,
    secret_enc_key: bytes,
) -> AuthorizationCodeTokenRequestResult | DevicePage:
    match maybe_app_idp:
        case AppIdpIdentityProvider(app_idp, idp):
            return AuthorizationCodeTokenRequestResult(
                idp,
                create_idp_token_request(
                    app_idp, code, state.code_verifier, callback_url, secret_enc_key
                ),
            )
        case None:
            return DevicePage.ERROR
        case unreachable:
            assert_never(unreachable)


def device_approval_page(approved: bool) -> DevicePage:
    # Approval fails if the code was already used, denied, or has expired.
    return DevicePage.APPROVED if approved else DevicePage.INVALID_CODE


class CreateDeviceSessionResult(NamedTuple):
    session: Session
    session_grant: DeviceCodeSessionGrant


def create_device_session(
    state: DeviceIdpAuthorizationState,
    user: User,
    session_id: str,
    time: datetime,
) -> CreateDeviceSessionResult:
    return CreateDeviceSessionResult(
        Session(
            session_id=session_id,
            client_id=state.client_id,
            user_id=user.user_id,
            idp_issuer=state.idp_issuer,
            scope=state.request_scope,
            issued_at=time,
        ),
        DeviceCodeSessionGrant(
            grant_type=SessionGrantType.DEVICE_CODE,
            token_hash=state.request_state.device_code_hash,
            session_id=session_id,
            state=SessionState(),
            issued_at=time,
        ),
    )
