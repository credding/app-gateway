from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.device_authorization import (
    CheckDeviceVerificationResult,
    CreateDeviceAuthorizationResult,
    DevicePage,
    ParseDeviceAuthorizationRequestResult,
    check_device_verification,
    create_device_authorization,
    create_device_idp_authorization_redirect,
    is_same_origin_request,
    parse_device_authorization_request,
    parse_device_verification_user_code,
)
from app_gateway.auth_server.grants.common import (
    AuthenticateClientResult,
    authenticate_client,
)
from app_gateway.auth_server.policy_manager import (
    lookup_app_access_rule,
    lookup_client,
    lookup_client_app_idps,
)
from app_gateway.auth_server.session_manager import (
    lookup_pending_device_authorization,
    save_device_authorization,
    save_idp_authorization_state,
)
from app_gateway.auth_server.templates import render_device_page
from app_gateway.common.clock import now
from app_gateway.common.validation import parse_form_params
from app_gateway.oauth import (
    generate_code_verifier,
    generate_device_code,
    generate_state_token,
    generate_user_code,
)
from app_gateway.policy import AccessType, ClientType
from app_gateway.settings import Settings, get_settings

router = APIRouter()


@router.post("/oauth/device_authorization")
async def oauth_device_authorization(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    params = parse_form_params((await api_request.form()).multi_items())
    time = now()

    match parse_device_authorization_request(
        params, api_request.headers.get("authorization")
    ):
        case ParseDeviceAuthorizationRequestResult(request, credentials):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_client = await lookup_client(credentials.client_id)

    match authenticate_client(maybe_client, credentials, settings):
        case AuthenticateClientResult(client, _, _):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_access_rule = (
        await lookup_app_access_rule(
            client.client_id,
            request.resource,
            AccessType.PUBLIC
            if client.client_type is ClientType.PUBLIC
            else AccessType.AUTHENTICATED,
        )
        if request.resource is not None
        else None
    )

    match create_device_authorization(
        client.client_id,
        request,
        maybe_access_rule,
        generate_device_code(),
        generate_user_code(),
        str(api_request.url_for("oauth_device")),
        time,
        settings.device_code_lifetime,
        settings.device_code_interval,
    ):
        case CreateDeviceAuthorizationResult(device_auth, response):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    await save_device_authorization(device_auth)

    return response


@router.get("/oauth/device")
async def oauth_device(api_request: Request) -> Response:
    # verification_uri_complete only pre-fills the form; the user still submits
    # it, which keeps the same-origin check and lets them confirm the code.
    return render_device_page(
        api_request,
        DevicePage.ENTER_CODE,
        api_request.query_params.get("user_code"),
    )


@router.post("/oauth/device")
async def oauth_device_verify(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    # Without this, a cross-site form post combined with silent IdP SSO would
    # approve an attacker's device code with the victim's identity.
    if not is_same_origin_request(
        api_request.headers.get("origin"), settings.auth_server_issuer
    ):
        return render_device_page(api_request, DevicePage.ERROR)

    params = parse_form_params((await api_request.form()).multi_items())
    time = now()

    maybe_user_code = parse_device_verification_user_code(params)
    maybe_device_auth = (
        await lookup_pending_device_authorization(maybe_user_code)
        if maybe_user_code is not None
        else None
    )
    maybe_client_app_idps = (
        await lookup_client_app_idps(maybe_device_auth.client_id)
        if maybe_device_auth is not None
        else None
    )

    match check_device_verification(
        maybe_device_auth,
        maybe_client_app_idps,
        time,
        settings.device_code_lifetime,
    ):
        case CheckDeviceVerificationResult(device_auth, app_idp, idp):
            pass
        case DevicePage() as page:
            return render_device_page(api_request, page)
        case unreachable:
            assert_never(unreachable)

    state, response = create_device_idp_authorization_redirect(
        device_auth,
        app_idp,
        idp,
        generate_state_token(),
        generate_code_verifier(),
        str(api_request.url_for("oauth_broker_callback", idp_slug=idp.slug)),
        time,
    )

    await save_idp_authorization_state(state)

    return response
