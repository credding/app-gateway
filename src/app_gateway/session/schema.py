import enum
from datetime import datetime, timedelta
from typing import Annotated, Literal

from joserfc import jwt
from pydantic import BaseModel, Field

from app_gateway.oauth import CodeChallengeMethod


class AuthorizationScope(BaseModel):
    resource: str | None = None
    scope: str | None = None


class AuthorizationState(BaseModel):
    code_challenge: str
    code_challenge_method: CodeChallengeMethod
    redirect_uri: str
    state: str


class SessionState(BaseModel):
    pass


class Session(BaseModel):
    session_id: str
    client_id: str
    user_id: str
    idp_issuer: str
    scope: AuthorizationScope
    issued_at: datetime
    revoked_at: datetime | None = None


class SessionGrantType(enum.StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class _SessionGrant[K: SessionGrantType, T](BaseModel):
    grant_type: K
    token_hash: bytes
    session_id: str
    state: T
    issued_at: datetime
    invalidated_at: datetime | None = None


class AuthorizationCodeSessionGrant(
    _SessionGrant[
        Literal[SessionGrantType.AUTHORIZATION_CODE],
        AuthorizationState,
    ]
):
    pass


class RefreshTokenSessionGrant(
    _SessionGrant[
        Literal[SessionGrantType.REFRESH_TOKEN],
        SessionState,
    ]
):
    pass


type SessionGrant = Annotated[
    AuthorizationCodeSessionGrant | RefreshTokenSessionGrant,
    Field(discriminator="grant_type"),
]


class AccessTokenLog(BaseModel):
    session_id: str
    scope: AuthorizationScope
    header: jwt.Header
    claims: jwt.Claims
    issued_at: datetime


class IdpAuthorizationState(BaseModel):
    state_hash: bytes
    client_id: str
    request_scope: AuthorizationScope
    request_state: AuthorizationState
    idp_slug: str
    idp_issuer: str
    code_verifier: str
    issued_at: datetime


class IdpSession(BaseModel):
    client_id: str
    user_id: str
    idp_issuer: str
    expires_in: timedelta | None
    refresh_token_enc: bytes | None
    issued_at: datetime
