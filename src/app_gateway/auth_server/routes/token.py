from datetime import datetime
from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization import lookup_app_access_rule
from app_gateway.auth_server.authorization_code import (
    AuthorizationCodeGrantResult,
    AuthorizationCodeReplayResult,
    CreateTokenResponseResult,
    ParseTokenRequestResult,
    authenticate_client,
    create_authorization_code_token_response,
    lookup_client,
    parse_authorization_code_grant,
    parse_token_request,
    redeem_authorization_code,
    revoke_session,
    save_authorization_code_tokens,
    unsupported_grant_type_response,
)
from app_gateway.common.clock import now
from app_gateway.common.jose import get_token_signing_key
from app_gateway.common.tokens import generate_id_token
from app_gateway.common.validation import parse_form_params
from app_gateway.oauth import AuthorizationCodeTokenRequest, generate_refresh_token
from app_gateway.policy import Client
from app_gateway.settings import Settings, get_settings

router = APIRouter()


@router.post("/oauth/token")
async def oauth_token(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    params = parse_form_params((await api_request.form()).multi_items())
    time = now()

    match parse_token_request(params, api_request.headers.get("authorization")):
        case ParseTokenRequestResult(request, credentials):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_client = await lookup_client(credentials.client_id)

    match authenticate_client(maybe_client, credentials):
        case Response() as error_response:
            return error_response
        case client:
            pass

    match request:
        case AuthorizationCodeTokenRequest():
            return await _authorization_code_grant(settings, client, request, time)
        case _:
            return unsupported_grant_type_response()


async def _authorization_code_grant(
    settings: Settings,
    client: Client,
    request: AuthorizationCodeTokenRequest,
    time: datetime,
) -> Response:
    maybe_redeemed = await redeem_authorization_code(request.code, time)

    match parse_authorization_code_grant(
        maybe_redeemed,
        client,
        request,
        time,
        settings.authorization_code_lifetime,
    ):
        case AuthorizationCodeGrantResult(session, request_scope, access_type):
            pass
        case AuthorizationCodeReplayResult(session_id, error_response):
            await revoke_session(session_id, time)
            return error_response
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_access_rule = (
        await lookup_app_access_rule(
            client.client_id,
            request_scope.resource,
            access_type,
        )
        if request_scope.resource is not None
        else None
    )

    match create_authorization_code_token_response(
        session,
        client,
        request_scope,
        maybe_access_rule,
        get_token_signing_key(
            settings.token_signing_key_seed.get_secret_value(),
            time,
            settings.key_rotation_schedule,
        ),
        generate_id_token(),
        generate_refresh_token(),
        settings.auth_server_issuer,
        time,
        settings.access_token_lifetime,
    ):
        case CreateTokenResponseResult(access_token_log, refresh_grant, response):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    await save_authorization_code_tokens(access_token_log, refresh_grant)

    return response
