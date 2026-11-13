from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, NamedTuple
from urllib.parse import unquote_plus

from fastapi import APIRouter, Depends, Request, Response
from joserfc import jwt
from pydantic import ValidationError

from app_gateway.auth_server.policy_manager import (
    lookup_app_access_rule,
    lookup_client,
)
from app_gateway.auth_server.session_manager import (
    invalidate_authorization_code_state,
    restore_authorization_code_state,
    revoke_session,
    save_access_token_log,
    save_refresh_token_state,
)
from app_gateway.common.base64 import base64decode
from app_gateway.common.clock import now, to_seconds, to_timestamp
from app_gateway.common.jose import get_token_signing_key
from app_gateway.common.tokens import (
    generate_id_token,
    hash_token,
    verify_token,
)
from app_gateway.common.validation import validate_params
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    TokenError,
    TokenErrorResponse,
    TokenRequest,
    TokenResponse,
    generate_refresh_token,
    verify_code_challenge,
)
from app_gateway.oauth.responses import OauthResponse
from app_gateway.policy import (
    AccessType,
    Client,
    ClientType,
    ConfidentialClient,
)
from app_gateway.session import (
    AccessTokenLog,
    AuthorizationRequestScope,
    RefreshTokenState,
)
from app_gateway.settings import Settings, get_settings

router = APIRouter()

_NO_STORE_HEADERS = {"cache-control": "no-store", "pragma": "no-cache"}


@router.post("/oauth/token")
async def oauth_token(
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    params = (await api_request.form()).multi_items()

    try:
        request = validate_params(TokenRequest, params)
    except ValidationError as e:
        match e.errors():
            case [
                {"type": "union_tag_invalid", "loc": (), "input": {"grant_type": str()}}
            ]:
                return _error_response(TokenError.UNSUPPORTED_GRANT_TYPE)
            case _:
                return _error_response(TokenError.INVALID_REQUEST)

    client_or_error = await _authenticate_client(
        api_request.headers.get("authorization"),
        request.client_id,
        request.client_secret,
    )
    if isinstance(client_or_error, Response):
        return client_or_error
    client = client_or_error

    match request:
        case AuthorizationCodeTokenRequest():
            return await _authorization_code_grant(settings, client, request)
        case _:
            return _error_response(TokenError.UNSUPPORTED_GRANT_TYPE)


async def _authorization_code_grant(
    settings: Settings,
    client: Client,
    request: AuthorizationCodeTokenRequest,
) -> Response:
    time = now()

    code_hash = hash_token(request.code)
    code_state = await restore_authorization_code_state(code_hash)
    if code_state is None:
        return _error_response(TokenError.INVALID_GRANT)

    code_replayed = not await invalidate_authorization_code_state(code_hash, time)

    request_state = code_state.request_state

    if (
        code_state.client_id != client.client_id
        or time - code_state.issued_at > settings.authorization_code_lifetime
        or (
            request.redirect_uri is not None
            and request.redirect_uri != request_state.redirect_uri
        )
        or not verify_code_challenge(
            request.code_verifier, request_state.code_challenge
        )
    ):
        return _error_response(TokenError.INVALID_GRANT)

    if code_replayed:
        await revoke_session(code_hash, time)
        return _error_response(TokenError.INVALID_GRANT)

    granted_scope = code_state.request_scope
    resource = granted_scope.resource

    if request.resource is not None and request.resource != resource:
        return _error_response(TokenError.INVALID_TARGET)

    scope = granted_scope.scope
    if request.scope is not None:
        granted_scopes = set((granted_scope.scope or "").split())
        if not set(request.scope.split()) <= granted_scopes:
            return _error_response(TokenError.INVALID_SCOPE)
        scope = request.scope

    if resource is not None:
        access_type = (
            AccessType.PUBLIC
            if client.client_type is ClientType.PUBLIC
            else AccessType.AUTHENTICATED
        )
        access_rule = await lookup_app_access_rule(
            client.client_id, resource, access_type
        )
        if access_rule is None:
            return _error_response(TokenError.INVALID_TARGET)

    request_scope = AuthorizationRequestScope(resource=resource, scope=scope)

    access_token = await _issue_access_token(
        settings,
        client.client_id,
        code_state.user_id,
        request_scope,
        time,
    )

    refresh_token = generate_refresh_token()
    await save_refresh_token_state(
        RefreshTokenState(
            refresh_token_hash=hash_token(refresh_token),
            code_hash=code_hash,
            client_id=client.client_id,
            user_id=code_state.user_id,
            request_scope=request_scope,
            idp_issuer=code_state.idp_issuer,
            issued_at=time,
        )
    )

    return OauthResponse(
        TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=to_seconds(settings.access_token_lifetime),
            scope=scope,
            refresh_token=refresh_token,
        ),
        headers=_NO_STORE_HEADERS,
    )


class _BasicCredentials(NamedTuple):
    client_id: str
    client_secret: str


async def _authenticate_client(
    authorization: str | None,
    body_client_id: str | None,
    body_client_secret: str | None,
) -> Client | Response:
    basic: _BasicCredentials | None = None
    if authorization is not None:
        basic = _parse_basic_credentials(authorization)
        if basic is None:
            return _invalid_client(basic=True)

    if basic is not None:
        if body_client_secret is not None:
            return _error_response(TokenError.INVALID_REQUEST)
        if body_client_id is not None and body_client_id != basic.client_id:
            return _error_response(TokenError.INVALID_REQUEST)
        client_id, client_secret = basic
    else:
        if body_client_id is None:
            return _invalid_client(basic=False)
        client_id, client_secret = body_client_id, body_client_secret

    client = await lookup_client(client_id)
    if client is None:
        return _invalid_client(basic=basic is not None)

    if isinstance(client, ConfidentialClient):
        if client_secret is None or not verify_token(
            client_secret, client.client_secret_hash
        ):
            return _invalid_client(basic=basic is not None)
    elif client_secret is not None:
        return _invalid_client(basic=basic is not None)

    return client


def _parse_basic_credentials(authorization: str) -> _BasicCredentials | None:
    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "basic":
        return None

    try:
        decoded = base64decode(credentials.strip().encode()).decode()
    except ValueError:
        return None

    client_id, sep, client_secret = decoded.partition(":")
    if not sep or not client_id:
        return None

    # RFC 6749 Section 2.3.1: credentials are form-urlencoded before base64.
    return _BasicCredentials(unquote_plus(client_id), unquote_plus(client_secret))


async def _issue_access_token(
    settings: Settings,
    client_id: str,
    user_id: str,
    request_scope: AuthorizationRequestScope,
    time: datetime,
) -> str:
    key = get_token_signing_key(
        settings.token_signing_key_seed.get_secret_value(),
        time,
        settings.key_rotation_schedule,
    )

    issued_at = to_timestamp(time)

    # RFC 9068 JWT profile for OAuth 2.0 access tokens.
    header: dict[str, Any] = {"alg": "ES256", "typ": "at+jwt", "kid": key.kid}
    claims: dict[str, Any] = {
        "iss": settings.auth_server_issuer,
        "sub": user_id,
        "aud": request_scope.resource or client_id,
        "client_id": client_id,
        "iat": issued_at,
        "exp": issued_at + to_seconds(settings.access_token_lifetime),
        "jti": generate_id_token(),
    }
    if request_scope.scope is not None:
        claims["scope"] = request_scope.scope

    access_token = jwt.encode(header, claims, key)

    await save_access_token_log(
        AccessTokenLog(
            request_scope=request_scope,
            header=header,
            claims=claims,
            issued_at=time,
        )
    )

    return access_token


def _error_response(
    error: TokenError,
    status_code: int = 400,
    headers: Mapping[str, str] | None = None,
) -> Response:
    return OauthResponse(
        TokenErrorResponse(error=error),
        status_code=status_code,
        headers={**_NO_STORE_HEADERS, **(headers or {})},
    )


def _invalid_client(*, basic: bool) -> Response:
    if basic:
        return _error_response(
            TokenError.INVALID_CLIENT,
            status_code=401,
            headers={"www-authenticate": 'Basic realm="token"'},
        )
    return _error_response(TokenError.INVALID_CLIENT)
