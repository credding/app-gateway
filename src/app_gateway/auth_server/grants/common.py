from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, NamedTuple, Protocol, assert_never
from urllib.parse import unquote_plus

from fastapi import Response
from joserfc import jwk, jwt
from pydantic import ValidationError

from app_gateway.auth_server.grants.id_token import create_id_token, has_openid_scope
from app_gateway.auth_server.policy_manager import UserIdentity
from app_gateway.common.base64 import base64decode
from app_gateway.common.clock import to_seconds, to_timestamp
from app_gateway.common.tokens import hash_token, verify_token
from app_gateway.common.validation import FormParams, type_adapter
from app_gateway.oauth import (
    TokenError,
    TokenErrorResponse,
    TokenRequest,
    TokenResponse,
)
from app_gateway.oauth.responses import OauthResponse
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    Client,
    ClientType,
    ConfidentialClient,
    PublicClient,
)
from app_gateway.session import (
    AccessTokenLog,
    AuthorizationScope,
    Session,
)
from app_gateway.session.schema import (
    RefreshTokenSessionGrant,
    SessionGrantType,
    SessionState,
)


class ParseTokenRequestResult(NamedTuple):
    request: TokenRequest
    credentials: ClientCredentials


class ClientCredentials(NamedTuple):
    client_id: str
    client_secret: str | None
    basic: bool


def parse_token_request(
    params: FormParams,
    authorization: str | None,
) -> ParseTokenRequestResult | Response:
    try:
        request = type_adapter(TokenRequest).validate_python(params)
    except ValidationError as e:
        match e.errors():
            case [
                {"type": "union_tag_invalid", "loc": (), "input": {"grant_type": str()}}
            ]:
                return token_error_response(TokenError.UNSUPPORTED_GRANT_TYPE)
            case list():
                return token_error_response(TokenError.INVALID_REQUEST)
            case unreachable:
                assert_never(unreachable)

    if authorization is not None:
        basic = _parse_basic_credentials(authorization)
        if basic is None:
            return _invalid_client(basic=True)
        if request.client_secret is not None:
            return token_error_response(TokenError.INVALID_REQUEST)
        if request.client_id is not None and request.client_id != basic.client_id:
            return token_error_response(TokenError.INVALID_REQUEST)
        credentials = ClientCredentials(
            basic.client_id, basic.client_secret, basic=True
        )
    elif request.client_id is not None:
        credentials = ClientCredentials(
            request.client_id, request.client_secret, basic=False
        )
    else:
        return _invalid_client(basic=False)

    return ParseTokenRequestResult(request, credentials)


class _BasicCredentials(NamedTuple):
    client_id: str
    client_secret: str


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


class AuthenticateClientResult(NamedTuple):
    client: Client
    session_lifetime: timedelta
    refresh_token_lifetime: timedelta


class SessionLifetimeSettings(Protocol):
    confidential_client_session_lifetime: timedelta
    confidential_client_refresh_token_lifetime: timedelta
    public_client_session_lifetime: timedelta
    public_client_refresh_token_lifetime: timedelta


def authenticate_client(
    maybe_client: Client | None,
    credentials: ClientCredentials,
    lifetime_settings: SessionLifetimeSettings,
) -> AuthenticateClientResult | Response:
    match maybe_client:
        case ConfidentialClient() as client if (
            credentials.client_secret is not None
            and verify_token(credentials.client_secret, client.client_secret_hash)
        ):
            return AuthenticateClientResult(
                client,
                lifetime_settings.confidential_client_session_lifetime,
                lifetime_settings.confidential_client_refresh_token_lifetime,
            )
        case PublicClient() as client if credentials.client_secret is None:
            return AuthenticateClientResult(
                client,
                lifetime_settings.public_client_session_lifetime,
                lifetime_settings.public_client_refresh_token_lifetime,
            )
        case ConfidentialClient() | PublicClient() | None:
            return _invalid_client(basic=credentials.basic)
        case unreachable:
            assert_never(unreachable)


class TokenGrantResult(NamedTuple):
    session: Session
    request_scope: AuthorizationScope
    access_type: AccessType
    nonce: str | None


class TokenReplayResult(NamedTuple):
    session_id: str
    response: Response


def narrow_request_scope(
    session: Session,
    client: Client,
    request: TokenRequest,
    nonce: str | None,
) -> TokenGrantResult | Response:
    granted_scope = session.scope
    resource = granted_scope.resource

    if request.resource is not None and request.resource != resource:
        return token_error_response(TokenError.INVALID_TARGET)

    scope = granted_scope.scope
    if request.scope is not None:
        granted_scopes = set((granted_scope.scope or "").split())
        if not set(request.scope.split()) <= granted_scopes:
            return token_error_response(TokenError.INVALID_SCOPE)
        scope = request.scope

    access_type = (
        AccessType.PUBLIC
        if client.client_type is ClientType.PUBLIC
        else AccessType.AUTHENTICATED
    )

    return TokenGrantResult(
        session,
        AuthorizationScope(resource=resource, scope=scope),
        access_type,
        nonce,
    )


class CreateTokenResponseResult(NamedTuple):
    access_token_log: AccessTokenLog
    refresh_token_grant: RefreshTokenSessionGrant
    response: Response


def create_token_response(
    session: Session,
    client: Client,
    request_scope: AuthorizationScope,
    maybe_access_rule: AppAccessRule | None,
    maybe_identity: UserIdentity | None,
    nonce: str | None,
    signing_key: jwk.Key,
    jti: str,
    refresh_token: str,
    issuer: str,
    time: datetime,
    access_token_lifetime: timedelta,
    id_token_lifetime: timedelta,
) -> CreateTokenResponseResult | Response:
    if request_scope.resource is not None and maybe_access_rule is None:
        return token_error_response(TokenError.INVALID_TARGET)

    openid = has_openid_scope(request_scope)
    if openid and maybe_identity is None:
        return token_error_response(TokenError.INVALID_GRANT)

    issued_at = to_timestamp(time)
    expires_in = to_seconds(access_token_lifetime)

    # RFC 9068 JWT profile for OAuth 2.0 access tokens.
    header: dict[str, Any] = {"alg": "ES256", "typ": "at+jwt", "kid": signing_key.kid}
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": session.user_id,
        "aud": request_scope.resource or client.client_id,
        "client_id": client.client_id,
        "iat": issued_at,
        "exp": issued_at + expires_in,
        "jti": jti,
    }
    if request_scope.scope is not None:
        claims["scope"] = request_scope.scope

    access_token = jwt.encode(header, claims, signing_key)

    id_token = (
        create_id_token(
            session,
            client,
            request_scope,
            maybe_identity,
            signing_key,
            nonce,
            issuer,
            time,
            id_token_lifetime,
        )
        if openid and maybe_identity is not None
        else None
    )

    return CreateTokenResponseResult(
        AccessTokenLog(
            session_id=session.session_id,
            scope=request_scope,
            header=header,
            claims=claims,
            issued_at=time,
        ),
        RefreshTokenSessionGrant(
            grant_type=SessionGrantType.REFRESH_TOKEN,
            token_hash=hash_token(refresh_token),
            state=SessionState(),
            session_id=session.session_id,
            issued_at=time,
        ),
        OauthResponse(
            TokenResponse(
                access_token=access_token,
                token_type="Bearer",
                expires_in=expires_in,
                scope=request_scope.scope,
                refresh_token=refresh_token,
                id_token=id_token,
            ),
        ),
    )


def _invalid_client(*, basic: bool) -> Response:
    if basic:
        return token_error_response(
            TokenError.INVALID_CLIENT,
            status_code=401,
            headers={"www-authenticate": 'Basic realm="token"'},
        )
    return token_error_response(TokenError.INVALID_CLIENT)


def unsupported_grant_type_response() -> Response:
    return token_error_response(TokenError.UNSUPPORTED_GRANT_TYPE)


def token_error_response(
    error: TokenError,
    status_code: int = 400,
    headers: Mapping[str, str] | None = None,
) -> Response:
    return OauthResponse(
        TokenErrorResponse(error=error),
        status_code=status_code,
        headers=headers,
    )
