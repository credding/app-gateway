import enum
from datetime import datetime, timedelta
from typing import Annotated, Literal

from joserfc import jwt
from pydantic import BaseModel, ConfigDict, Field

from app_gateway.oauth import CodeChallengeMethod, GrantType


class AuthorizationScope(BaseModel):
    resource: str | None = None
    scope: str | None = None


class AuthorizationState(BaseModel):
    code_challenge: str | None = None
    code_challenge_method: CodeChallengeMethod | None = None
    redirect_uri: str
    state: str
    nonce: str | None = None


class DeviceAuthorizationState(BaseModel):
    model_config = ConfigDict(ser_json_bytes="base64", val_json_bytes="base64")

    device_code_hash: bytes


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
    DEVICE_CODE = GrantType.DEVICE_CODE.value


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


class DeviceCodeSessionGrant(
    _SessionGrant[
        Literal[SessionGrantType.DEVICE_CODE],
        SessionState,
    ]
):
    pass


type SessionGrant = Annotated[
    AuthorizationCodeSessionGrant | RefreshTokenSessionGrant | DeviceCodeSessionGrant,
    Field(discriminator="grant_type"),
]


class AccessTokenLog(BaseModel):
    session_id: str
    scope: AuthorizationScope
    header: jwt.Header
    claims: jwt.Claims
    issued_at: datetime


class _IdpAuthorizationState[T](BaseModel):
    state_hash: bytes
    client_id: str
    request_scope: AuthorizationScope
    request_state: T
    idp_slug: str
    idp_issuer: str
    code_verifier: str
    issued_at: datetime


class IdpAuthorizationState(_IdpAuthorizationState[AuthorizationState]):
    pass


class DeviceIdpAuthorizationState(_IdpAuthorizationState[DeviceAuthorizationState]):
    pass


type AnyIdpAuthorizationState = IdpAuthorizationState | DeviceIdpAuthorizationState


class DeviceAuthorization(BaseModel):
    device_code_hash: bytes
    user_code_hash: bytes
    client_id: str
    request_scope: AuthorizationScope
    issued_at: datetime
    approved_at: datetime | None = None
    denied_at: datetime | None = None


class IdpSession(BaseModel):
    client_id: str
    user_id: str
    idp_issuer: str
    expires_in: timedelta | None
    refresh_token_enc: bytes | None
    issued_at: datetime
