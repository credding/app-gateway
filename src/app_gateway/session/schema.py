from datetime import datetime

from joserfc import jwt
from pydantic import BaseModel

from app_gateway.oauth import CodeChallengeMethod, GrantType


class AuthorizationScope(BaseModel):
    resource: str | None = None
    scope: str | None = None


class AuthorizationState(BaseModel):
    code_challenge: str
    code_challenge_method: CodeChallengeMethod
    redirect_uri: str
    state: str


class Session(BaseModel):
    session_id: str
    client_id: str
    user_id: str
    idp_issuer: str
    scope: AuthorizationScope
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class SessionGrant(BaseModel):
    token_hash: bytes
    grant_type: GrantType
    session_id: str
    issued_at: datetime
    invalidated_at: datetime | None = None


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
    refresh_token_enc: bytes
    issued_at: datetime
    expires_at: datetime | None
