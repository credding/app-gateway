from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints


class AuthorizationServerMetadata(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str
    jwks_uri: str
    response_types_supported: list[ResponseType]
    grant_types_supported: list[GrantType]
    token_endpoint_auth_methods_supported: list[str]
    code_challenge_methods_supported: list[CodeChallengeMethod]
    authorization_response_iss_parameter_supported: bool
    scopes_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]


class ResponseType(StrEnum):
    CODE = "code"


class CodeChallengeMethod(StrEnum):
    S256 = "S256"


class AuthorizationRequest(BaseModel):
    response_type: ResponseType
    client_id: str
    code_challenge: Annotated[
        str | None, StringConstraints(pattern=r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")
    ] = None
    code_challenge_method: CodeChallengeMethod | None = None
    redirect_uri: str
    resource: str | None = None
    scope: str | None = None
    state: Annotated[str, StringConstraints(min_length=1)]
    nonce: str | None = None


class AuthorizationResponse(BaseModel):
    code: str
    state: str
    iss: str


class AuthorizationError(StrEnum):
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_TARGET = "invalid_target"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


class AuthorizationErrorResponse(BaseModel):
    error: AuthorizationError
    error_description: str | None = None
    error_uri: str | None = None
    state: str | None = None
    iss: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: Annotated[str, StringConstraints(pattern=r"(?i)^bearer$")]
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None


class TokenError(StrEnum):
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_TARGET = "invalid_target"
    INVALID_SCOPE = "invalid_scope"
    AUTHORIZATION_PENDING = "authorization_pending"
    ACCESS_DENIED = "access_denied"
    EXPIRED_TOKEN = "expired_token"


class TokenErrorResponse(BaseModel):
    error: TokenError
    error_description: str | None = None
    error_uri: str | None = None


class GrantType(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


class _BaseTokenRequest(BaseModel):
    client_id: str | None = None
    client_secret: str | None = None
    resource: str | None = None
    scope: str | None = None


class AuthorizationCodeTokenRequest(_BaseTokenRequest):
    grant_type: Literal[GrantType.AUTHORIZATION_CODE]
    code: str
    code_verifier: Annotated[
        str | None, StringConstraints(pattern=r"^[A-Za-z0-9\-._~]{43,128}$")
    ] = None
    redirect_uri: str | None = None


class ClientCredentialsTokenRequest(_BaseTokenRequest):
    grant_type: Literal[GrantType.CLIENT_CREDENTIALS]


class RefreshTokenTokenRequest(_BaseTokenRequest):
    grant_type: Literal[GrantType.REFRESH_TOKEN]
    refresh_token: str


class DeviceCodeTokenRequest(_BaseTokenRequest):
    grant_type: Literal[GrantType.DEVICE_CODE]
    device_code: str


class TokenExchangeTokenType(StrEnum):
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


class TokenExchangeTokenRequest(_BaseTokenRequest):
    grant_type: Literal[GrantType.TOKEN_EXCHANGE]
    subject_token: str
    subject_token_type: TokenExchangeTokenType
    requested_token_type: TokenExchangeTokenType | None = None
    # Unsupported RFC 8693 parameters, parsed so they can be rejected explicitly.
    audience: str | None = None
    actor_token: str | None = None
    actor_token_type: str | None = None


class TokenExchangeTokenResponse(TokenResponse):
    issued_token_type: TokenExchangeTokenType


type TokenRequest = Annotated[
    AuthorizationCodeTokenRequest
    | ClientCredentialsTokenRequest
    | RefreshTokenTokenRequest
    | DeviceCodeTokenRequest
    | TokenExchangeTokenRequest,
    Field(discriminator="grant_type"),
]


class DeviceAuthorizationRequest(BaseModel):
    client_id: str | None = None
    client_secret: str | None = None
    resource: str | None = None
    scope: str | None = None


class DeviceAuthorizationResponse(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
