from datetime import datetime, timedelta
from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.idp_authentication import (
    create_idp_session,
    lookup_app_access_rule,
    lookup_client_app_idp,
)
from app_gateway.auth_server.grants.authorization_code import (
    parse_authorization_code_grant,
)
from app_gateway.auth_server.grants.common import (
    AuthenticateClientResult,
    CreateTokenResponseResult,
    ParseTokenRequestResult,
    RestoreSessionGrantResult,
    TokenGrantResult,
    TokenReplayResult,
    authenticate_client,
    create_token_response,
    lookup_client,
    lookup_user_identity,
    parse_token_request,
    redeem_session_grant,
    restore_session_grant,
    revoke_session,
    save_idp_session,
    save_issued_tokens,
    unsupported_grant_type_response,
)
from app_gateway.auth_server.grants.id_token import has_openid_scope
from app_gateway.auth_server.grants.refresh_token import (
    IdpRefreshTokenRequestResult,
    IdpSessionRefresh,
    IdpSessionValid,
    SessionEndedResult,
    check_idp_session,
    check_refresh_token_grant,
    create_idp_refresh_token_request,
    idp_session_ended,
    parse_refresh_token_grant,
)
from app_gateway.auth_server.idp_client import (
    IdpGrantRejected,
    refresh_idp_token,
)
from app_gateway.common.clock import now
from app_gateway.common.jose import get_token_signing_key
from app_gateway.common.tokens import generate_id_token
from app_gateway.common.validation import parse_form_params
from app_gateway.crypto.encrypt import generate_nonce
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    GrantType,
    RefreshTokenTokenRequest,
    TokenResponse,
    generate_refresh_token,
)
from app_gateway.policy import Client
from app_gateway.session import IdpSession, Session
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
    maybe_restored = await restore_session_grant(
        request.refresh_token, GrantType.REFRESH_TOKEN
    )

    match check_refresh_token_grant(
        maybe_restored,
        client,
        time,
        session_lifetime,
        refresh_token_lifetime,
    ):
        case RestoreSessionGrantResult(_, session, maybe_idp_session):
            pass
        case TokenReplayResult(session_id, error_response):
            await revoke_session(session_id, time)
            return error_response
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    match await _check_idp_session(settings, session, maybe_idp_session, time):
        case None:
            pass
        case SessionEndedResult(session_id, error_response):
            await revoke_session(session_id, time)
            return error_response
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

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


async def _check_idp_session(
    settings: Settings,
    session: Session,
    maybe_idp_session: IdpSession | None,
    time: datetime,
) -> SessionEndedResult | Response | None:
    match check_idp_session(maybe_idp_session, session, time):
        case IdpSessionValid():
            return None
        case IdpSessionRefresh(idp_session):
            pass
        case SessionEndedResult() as ended:
            return ended
        case unreachable:
            assert_never(unreachable)

    secret_enc_key = settings.secret_encryption_key.get_secret_value()
    maybe_app_idp = await lookup_client_app_idp(session.client_id, session.idp_issuer)

    match create_idp_refresh_token_request(
        maybe_app_idp, idp_session, session, secret_enc_key
    ):
        case IdpRefreshTokenRequestResult(idp, idp_request):
            pass
        case SessionEndedResult() as ended:
            return ended
        case unreachable:
            assert_never(unreachable)

    match await refresh_idp_token(idp, idp_request):
        case TokenResponse() as token_response:
            pass
        case IdpGrantRejected():
            return idp_session_ended(session)
        case unreachable:
            assert_never(unreachable)

    refreshed_idp_session = create_idp_session(
        session.client_id,
        session.user_id,
        session.idp_issuer,
        token_response,
        time,
        secret_enc_key,
        generate_nonce(),
        idp_session.refresh_token_enc,
    )

    await save_idp_session(refreshed_idp_session)

    return None


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

    maybe_identity = (
        await lookup_user_identity(session.idp_issuer, session.user_id)
        if has_openid_scope(request_scope)
        else None
    )

    match create_token_response(
        session,
        client,
        request_scope,
        maybe_access_rule,
        maybe_identity,
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
