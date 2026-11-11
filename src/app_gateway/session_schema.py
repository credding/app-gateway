from datetime import datetime

from joserfc import jwt
from pydantic import BaseModel

from app_gateway.oauth import CodeChallengeMethod


class AuthorizationRequestScope(BaseModel):
    resource: str | None
    scope: str | None


class AuthorizationRequestState(BaseModel):
    code_challenge: str
    code_challenge_method: CodeChallengeMethod
    redirect_uri: str
    state: str


class IdpAuthorizationState(BaseModel):
    state_hash: bytes
    client_id: str
    request_scope: AuthorizationRequestScope
    request_state: AuthorizationRequestState
    idp_issuer: str
    idp_code_verifier: str
    issued_at: datetime


class AuthorizationCodeState(BaseModel):
    code_hash: bytes
    client_id: str
    user_id: str
    request_scope: AuthorizationRequestScope
    request_state: AuthorizationRequestState
    idp_issuer: str
    issued_at: datetime
    invalidated_at: datetime | None = None


class RefreshTokenState(BaseModel):
    refresh_token_hash: bytes
    code_hash: bytes
    client_id: str
    user_id: str
    request_scope: AuthorizationRequestScope
    idp_issuer: str
    issued_at: datetime
    invalidated_at: datetime | None = None


class IdpSession(BaseModel):
    client_id: str
    user_id: str
    idp_issuer: str
    idp_token_enc: bytes


class IdpToken(BaseModel):
    access_token: str
    refresh_token: str | None
    expires_at: datetime | None


class AccessTokenLog(BaseModel):
    request_scope: AuthorizationRequestScope
    header: jwt.Header
    claims: jwt.Claims
    issued_at: datetime
