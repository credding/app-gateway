from datetime import datetime, timedelta
from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.idp_authentication import (
    lookup_app_access_rule,
)
from app_gateway.auth_server.grants.authorization_code import (
    parse_authorization_code_grant,
)
from app_gateway.auth_server.grants.common import (
    AuthenticateClientResult,
    CreateTokenResponseResult,
    ParseTokenRequestResult,
    TokenGrantResult,
    TokenReplayResult,
    authenticate_client,
    create_token_response,
    lookup_client,
    lookup_user_by_id,
    parse_token_request,
    redeem_session_grant,
    revoke_session,
    save_issued_tokens,
    unsupported_grant_type_response,
)
from app_gateway.auth_server.grants.id_token import has_openid_scope
from app_gateway.auth_server.grants.refresh_token import parse_refresh_token_grant
from app_gateway.common.clock import now
from app_gateway.common.jose import get_token_signing_key
from app_gateway.common.tokens import generate_id_token
from app_gateway.common.validation import parse_form_params
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    GrantType,
    RefreshTokenTokenRequest,
    generate_refresh_token,
)
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

    match authenticate_client(maybe_client, credentials, settings):
        case Response() as error_response:
            return error_response
        case AuthenticateClientResult(client, session_lifetime, refresh_token_lifetime):
            pass
        case unreachable:
            assert_never(unreachable)

    match request:
        case AuthorizationCodeTokenRequest():
            return await _authorization_code_grant(
                settings,
                client,
                request,
                session_lifetime,
                time,
            )
        case RefreshTokenTokenRequest():
            return await _refresh_token_grant(
                settings,
                client,
                request,
                session_lifetime,
                refresh_token_lifetime,
                time,
            )
        case _:
            return unsupported_grant_type_response()


async def _authorization_code_grant(
    settings: Settings,
    client: Client,
    request: AuthorizationCodeTokenRequest,
    session_lifetime: timedelta,
    time: datetime,
) -> Response:
    maybe_redeemed = await redeem_session_grant(
        request.code, GrantType.AUTHORIZATION_CODE, time
    )

    match parse_authorization_code_grant(
        maybe_redeemed,
        client,
        request,
        time,
        session_lifetime,
        settings.authorization_code_lifetime,
    ):
        case TokenGrantResult() as grant:
            pass
        case TokenReplayResult(session_id, error_response):
            await revoke_session(session_id, time)
            return error_response
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    return await _issue_tokens(settings, client, grant, time)


async def _refresh_token_grant(
    settings: Settings,
    client: Client,
    request: RefreshTokenTokenRequest,
    session_lifetime: timedelta,
    refresh_token_lifetime: timedelta,
    time: datetime,
) -> Response:
    maybe_redeemed = await redeem_session_grant(
        request.refresh_token, GrantType.REFRESH_TOKEN, time
    )

    match parse_refresh_token_grant(
        maybe_redeemed,
        client,
        request,
        time,
        session_lifetime,
        refresh_token_lifetime,
    ):
        case TokenGrantResult() as grant:
            pass
        case TokenReplayResult(session_id, error_response):
            await revoke_session(session_id, time)
            return error_response
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    return await _issue_tokens(settings, client, grant, time)


async def _issue_tokens(
    settings: Settings,
    client: Client,
    grant: TokenGrantResult,
    time: datetime,
) -> Response:
    session, request_scope, access_type, nonce = grant

    maybe_access_rule = (
        await lookup_app_access_rule(
            client.client_id,
            request_scope.resource,
            access_type,
        )
        if request_scope.resource is not None
        else None
    )

    maybe_user = (
        await lookup_user_by_id(session.user_id)
        if has_openid_scope(request_scope)
        else None
    )

    match create_token_response(
        session,
        client,
        request_scope,
        maybe_access_rule,
        maybe_user,
        nonce,
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
        settings.id_token_lifetime,
    ):
        case CreateTokenResponseResult(access_token_log, refresh_grant, response):
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    await save_issued_tokens(access_token_log, refresh_grant)

    return response
