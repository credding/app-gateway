from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints


class ResponseType(StrEnum):
    CODE = "code"


class GrantType(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class CodeChallengeMethod(StrEnum):
    S256 = "S256"


class AuthorizationServerMetadata(BaseModel):
    issuer: str
    authorization_enpdoint: str
    token_endpoint: str
    jwks_uri: str
    response_types_supported: list[ResponseType]
    grant_types_supported: list[GrantType]
    token_endpoint_auth_methods_supported: list[str]
    token_endpoint_signing_alg_values_supported: list[str]
    code_challenge_methods_supported: list[CodeChallengeMethod]


class AuthorizationRequest(BaseModel):
    response_type: ResponseType
    client_id: str
    code_challenge: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")
    ]
    code_challenge_method: CodeChallengeMethod
    redirect_uri: str
    resource: str | None = None
    scope: str | None = None
    state: Annotated[str, StringConstraints(min_length=1)]


class AuthorizationResponse(BaseModel):
    code: str
    state: str
    iss: str


class AuthorizationResponseCompat(BaseModel):
    code: str
    state: str
    iss: str | None


class AuthorizationError(StrEnum):
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
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


class AuthorizationErrorResponseCompat(BaseModel):
    error: str
    error_description: str
    error_uri: str
    state: str
    iss: str | None


class BaseTokenRequest(BaseModel):
    client_id: str | None
    client_secret: str | None
    resource: str | None = None
    scope: str | None = None


class TokenType(StrEnum):
    BEARER = "Bearer"


class TokenResponse(BaseModel):
    access_token: str
    token_type: TokenType
    expires_in: int | None
    scope: str | None
    refresh_token: str | None


class TokenError(StrEnum):
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_TARGET = "invalid_target"
    INVALID_SCOPE = "invalid_scope"


class TokenErrorResponse(BaseModel):
    error: TokenError
    error_description: str | None = None
    error_uri: str | None = None


class AuthorizationCodeTokenRequest(BaseTokenRequest):
    grant_type: Literal[GrantType.AUTHORIZATION_CODE]
    code: str
    code_verifier: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9\-._~]{43,128}$")
    ]


class ClientCredentialsTokenRequest(BaseTokenRequest):
    grant_type: Literal[GrantType.CLIENT_CREDENTIALS]


class RefreshTokenTokenRequest(BaseTokenRequest):
    grant_type: Literal[GrantType.REFRESH_TOKEN]
    refresh_token: str


class TokenExchangeTokenType(StrEnum):
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


class TokenExchangeTokenRequest(BaseTokenRequest):
    grant_type: Literal[GrantType.TOKEN_EXCHANGE]
    subject_token: str
    subject_token_type: TokenExchangeTokenType


class TokenExchangeTokenResponse(TokenResponse):
    issued_token_type: TokenExchangeTokenType


type TokenRequest = Annotated[
    AuthorizationCodeTokenRequest
    | ClientCredentialsTokenRequest
    | RefreshTokenTokenRequest
    | TokenExchangeTokenRequest,
    Field(discriminator="grant_type"),
]
