from datetime import datetime
from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.common import (
    parse_idp_authorization_callback_response,
)
from app_gateway.auth_server.authorization.device_authorization import (
    DeviceCallbackDenied,
    DevicePage,
    ParseDeviceCallbackResponseResult,
    create_device_idp_token_request,
    create_device_session,
    device_approval_page,
)
from app_gateway.auth_server.authorization.idp_authentication import (
    AuthorizationCodeTokenRequestResult,
    CreateIdpAuthorizationRedirectResult,
    ParseAuthorizationCallbackResponseResult,
    ParseAuthorizationRequestResult,
    create_authorization_code_response_redirect,
    create_idp_authorization_code_token_request,
    create_idp_authorization_redirect,
    create_idp_session,
    parse_authorization_callback_state_token,
    parse_authorization_request,
    parse_authorization_request_client_id,
)
from app_gateway.auth_server.idp_client import (
    map_userinfo_claims,
    request_idp_token,
    request_idp_userinfo,
)
from app_gateway.auth_server.policy_manager import (
    lookup_app_access_rule,
    lookup_client_app_idp,
    lookup_client_app_idps,
    lookup_user,
    register_user,
    update_user_claims,
)
from app_gateway.auth_server.session_manager import (
    approve_device_authorization,
    deny_device_authorization,
    initialize_session,
    invalidate_idp_authorization_state,
    save_idp_authorization_state,
)
from app_gateway.auth_server.templates import render_device_page
from app_gateway.common.clock import now
from app_gateway.common.tokens import generate_id_token
from app_gateway.common.validation import parse_form_params
from app_gateway.crypto.encrypt import generate_nonce
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    TokenResponse,
    generate_authorization_code,
    generate_code_verifier,
    generate_state_token,
)
from app_gateway.policy import IdentityProvider, User, generate_user_id
from app_gateway.session import DeviceIdpAuthorizationState
from app_gateway.settings import Settings, get_settings

router = APIRouter()


@router.get("/oauth/authorize")
async def oauth_authorize(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    params = parse_form_params(api_request.query_params.multi_items())

    maybe_client_id = parse_authorization_request_client_id(params)
    maybe_client_app_idps = (
        await lookup_client_app_idps(maybe_client_id)
        if maybe_client_id is not None
        else None
    )

    match parse_authorization_request(
        maybe_client_app_idps,
        params,
        settings.auth_server_issuer,
    ):
        case ParseAuthorizationRequestResult(request, app_idp, idp, access_type):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_access_rule = (
        await lookup_app_access_rule(
            request.client_id,
            request.resource,
            access_type,
        )
        if request.resource is not None
        else None
    )

    match create_idp_authorization_redirect(
        request,
        app_idp,
        idp,
        maybe_access_rule,
        generate_state_token(),
        generate_code_verifier(),
        str(api_request.url_for("oauth_broker_callback", idp_slug=idp.slug)),
        now(),
        settings.auth_server_issuer,
    ):
        case CreateIdpAuthorizationRedirectResult(state, response):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    await save_idp_authorization_state(state)

    return response


@router.get("/oauth/broker/{idp_slug}/callback")
async def oauth_broker_callback(
    api_request: Request,
    idp_slug: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    params = parse_form_params(api_request.query_params.multi_items())
    time = now()

    maybe_state_token = parse_authorization_callback_state_token(params)
    maybe_state = (
        await invalidate_idp_authorization_state(maybe_state_token, idp_slug)
        if maybe_state_token is not None
        else None
    )

    match parse_idp_authorization_callback_response(
        maybe_state,
        params,
        time,
        settings.auth_server_issuer,
        settings.idp_authorization_state_lifetime,
    ):
        case ParseAuthorizationCallbackResponseResult(state, code):
            pass
        case ParseDeviceCallbackResponseResult(device_state, code):
            return await _device_broker_callback(
                api_request, device_state, code, idp_slug, settings, time
            )
        case DeviceCallbackDenied(device_state):
            await deny_device_authorization(
                device_state.request_state.device_code_hash,
                time,
                time - settings.device_code_lifetime,
            )
            return render_device_page(api_request, DevicePage.DENIED)
        case DevicePage() as page:
            return render_device_page(api_request, page)
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_app_idp = await lookup_client_app_idp(state.client_id, state.idp_issuer)

    match create_idp_authorization_code_token_request(
        maybe_app_idp,
        state,
        code,
        str(api_request.url_for("oauth_broker_callback", idp_slug=idp_slug)),
        settings.auth_server_issuer,
        settings.secret_encryption_key.get_secret_value(),
    ):
        case AuthorizationCodeTokenRequestResult(idp, token_request):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    token_response, user = await _authenticate_idp_user(idp, token_request, time)

    idp_session = create_idp_session(
        state.client_id,
        user.user_id,
        state.idp_issuer,
        token_response,
        time,
        settings.secret_encryption_key.get_secret_value(),
        generate_nonce(),
    )

    session, session_grant, response = create_authorization_code_response_redirect(
        state,
        user,
        generate_id_token(),
        generate_authorization_code(),
        settings.auth_server_issuer,
        time,
    )

    await initialize_session(idp_session, session, session_grant)

    return response


async def _device_broker_callback(
    api_request: Request,
    state: DeviceIdpAuthorizationState,
    code: str,
    idp_slug: str,
    settings: Settings,
    time: datetime,
) -> Response:
    maybe_app_idp = await lookup_client_app_idp(state.client_id, state.idp_issuer)

    match create_device_idp_token_request(
        maybe_app_idp,
        state,
        code,
        str(api_request.url_for("oauth_broker_callback", idp_slug=idp_slug)),
        settings.secret_encryption_key.get_secret_value(),
    ):
        case AuthorizationCodeTokenRequestResult(idp, token_request):
            pass
        case DevicePage() as page:
            return render_device_page(api_request, page)
        case unreachable:
            assert_never(unreachable)

    token_response, user = await _authenticate_idp_user(idp, token_request, time)

    idp_session = create_idp_session(
        state.client_id,
        user.user_id,
        state.idp_issuer,
        token_response,
        time,
        settings.secret_encryption_key.get_secret_value(),
        generate_nonce(),
    )

    session, session_grant = create_device_session(
        state, user, generate_id_token(), time
    )

    approved = await approve_device_authorization(
        idp_session, session, session_grant, time, time - settings.device_code_lifetime
    )

    return render_device_page(api_request, device_approval_page(approved))


async def _authenticate_idp_user(
    idp: IdentityProvider,
    token_request: AuthorizationCodeTokenRequest,
    time: datetime,
) -> tuple[TokenResponse, User]:
    token_response = await request_idp_token(idp, token_request)
    userinfo_claims = await request_idp_userinfo(idp, token_response.access_token)
    idp_subject, claims = map_userinfo_claims(idp, userinfo_claims)

    user = await lookup_user(idp.issuer, idp_subject)
    if user is None:
        user = await register_user(
            idp.issuer,
            idp_subject,
            generate_user_id(),
            claims,
            time,
        )
    elif user.claims != claims:
        user = await update_user_claims(user, claims, time)

    return token_response, user
