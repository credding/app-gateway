from typing import Annotated, assert_never

from fastapi import APIRouter, Depends, Request, Response

from app_gateway.auth_server.authorization.userinfo import (
    check_userinfo_token,
    create_userinfo_response,
    parse_bearer_token,
)
from app_gateway.auth_server.grants.common import AccessTokenClaims
from app_gateway.auth_server.policy_manager import lookup_user_identity
from app_gateway.auth_server.session_manager import lookup_session
from app_gateway.common.clock import now
from app_gateway.common.jose import get_token_signing_keyset
from app_gateway.settings import Settings, get_settings

router = APIRouter()


@router.api_route("/oauth/userinfo", methods=["GET", "POST"])
async def oauth_userinfo(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    time = now()

    match parse_bearer_token(api_request.headers.get("authorization")):
        case str() as access_token:
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    match check_userinfo_token(
        access_token,
        get_token_signing_keyset(
            settings.token_signing_key_seed.get_secret_value(),
            time,
            settings.key_rotation_schedule,
        ),
        settings.auth_server_issuer,
        time,
    ):
        case AccessTokenClaims() as claims:
            pass
        case Response() as error_response:
            return error_response
        case unreachable:
            assert_never(unreachable)

    maybe_session = await lookup_session(claims.sid)
    maybe_identity = (
        await lookup_user_identity(maybe_session.idp_issuer, maybe_session.user_id)
        if maybe_session is not None
        else None
    )

    return create_userinfo_response(claims, maybe_session, maybe_identity)
