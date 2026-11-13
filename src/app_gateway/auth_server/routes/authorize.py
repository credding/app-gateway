from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization import (
    AuthorizationCodeTokenRequestResult,
    CreateIdpAuthorizationRedirectResult,
    ParseAuthorizationCallbackResponseResult,
    ParseAuthorizationRequestResult,
    create_authorization_code_response_redirect,
    create_idp_authorization_code_token_request,
    create_idp_authorization_redirect,
    create_idp_session,
    initialize_session,
    invalidate_idp_authorization_state,
    lookup_app_access_rule,
    lookup_client_app_idp,
    lookup_client_app_idps,
    lookup_user,
    parse_authorization_callback_response,
    parse_authorization_callback_state_token,
    parse_authorization_request,
    parse_authorization_request_client_id,
    register_user,
    save_idp_authorization_state,
    update_user_claims,
)
from app_gateway.auth_server.idp_client import (
    map_userinfo_claims,
    request_idp_token,
    request_idp_userinfo,
)
from app_gateway.common.clock import now
from app_gateway.common.tokens import generate_id_token
from app_gateway.common.validation import parse_form_params
from app_gateway.oauth import (
    generate_authorization_code,
    generate_code_verifier,
    generate_state_token,
)
from app_gateway.policy import generate_user_id
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

    match parse_authorization_callback_response(
        maybe_state,
        params,
        time,
        settings.auth_server_issuer,
        settings.idp_authorization_state_lifetime,
    ):
        case ParseAuthorizationCallbackResponseResult(state, code):
            pass
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

    token_response = await request_idp_token(idp, token_request)
    userinfo_claims = await request_idp_userinfo(idp, token_response.access_token)
    idp_subject, claims = map_userinfo_claims(idp, userinfo_claims)

    user = await lookup_user(state.idp_issuer, idp_subject)
    if user is None:
        user = await register_user(
            state.idp_issuer,
            idp_subject,
            generate_user_id(),
            claims,
            time,
        )
    elif user.claims != claims:
        user = await update_user_claims(user, claims, time)

    maybe_idp_session = create_idp_session(
        state.client_id,
        user.user_id,
        state.idp_issuer,
        token_response,
        time,
        settings.secret_encryption_key.get_secret_value(),
    )

    session, session_grant, response = create_authorization_code_response_redirect(
        state,
        user,
        generate_id_token(),
        generate_authorization_code(),
        settings.auth_server_issuer,
        time,
    )

    await initialize_session(maybe_idp_session, session, session_grant)

    return response
