import json
from typing import Self

from sqlalchemy import FetchedValue, Index
from sqlalchemy.dialects.sqlite import BLOB, INTEGER, TEXT
from sqlalchemy.orm import Mapped, mapped_column

from app_gateway.common.clock import to_timestamp
from app_gateway.db.policy_model import Base
from app_gateway.session import schema
from app_gateway.session.schema import AuthorizationScope, AuthorizationState


class Session(Base):
    __tablename__ = "session"

    session_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    user_id: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    scope: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    expires_at: Mapped[int] = mapped_column(INTEGER)
    revoked_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_session_expires_at", expires_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, session: schema.Session) -> Self:
        return cls(
            session_id=session.session_id,
            client_id=session.client_id,
            user_id=session.user_id,
            idp_issuer=session.idp_issuer,
            scope=session.scope.model_dump_json(exclude_none=True),
            issued_at=to_timestamp(session.issued_at),
            expires_at=to_timestamp(session.expires_at),
            revoked_at=to_timestamp(session.revoked_at),
        )

    def to_schema(self) -> schema.Session:
        return schema.Session(
            session_id=self.session_id,
            client_id=self.client_id,
            user_id=self.user_id,
            idp_issuer=self.idp_issuer,
            scope=AuthorizationScope.model_validate_json(self.scope),
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            revoked_at=self.revoked_at,
        )


class SessionGrant(Base):
    __tablename__ = "session_grant"

    token_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    grant_type: Mapped[str] = mapped_column(TEXT)
    session_id: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str | None] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    invalidated_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_session_grant_session_id", session_id),
        Index("ix_session_grant_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, grant: schema.SessionGrant) -> Self:
        return cls(
            token_hash=grant.token_hash,
            grant_type=grant.grant_type,
            session_id=grant.session_id,
            request_state=(
                grant.request_state.model_dump_json(exclude_none=True)
                if grant.request_state is not None
                else None
            ),
            issued_at=to_timestamp(grant.issued_at),
            invalidated_at=to_timestamp(grant.invalidated_at),
        )

    def to_schema(self) -> schema.SessionGrant:
        return schema.SessionGrant(
            token_hash=self.token_hash,
            grant_type=self.grant_type,
            session_id=self.session_id,
            request_state=(
                AuthorizationState.model_validate_json(self.request_state)
                if self.request_state is not None
                else None
            ),
            issued_at=self.issued_at,
            invalidated_at=self.invalidated_at,
        )


class AccessTokenLog(Base):
    __tablename__ = "access_token_log"

    rowid: Mapped[int] = mapped_column(
        INTEGER, system=True, server_default=FetchedValue()
    )
    session_id: Mapped[str] = mapped_column(TEXT)
    scope: Mapped[str] = mapped_column(TEXT)
    header: Mapped[str] = mapped_column(TEXT)
    claims: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __mapper_args__ = {"primary_key": [rowid], "eager_defaults": True}  # ruff: ignore[mutable-class-default]

    __table_args__ = (
        Index("ix_access_token_log_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, log: schema.AccessTokenLog) -> Self:
        return cls(
            session_id=log.session_id,
            scope=log.scope.model_dump_json(exclude_none=True),
            header=json.dumps(log.header),
            claims=json.dumps(log.claims),
            issued_at=to_timestamp(log.issued_at),
        )

    def to_schema(self) -> schema.AccessTokenLog:
        return schema.AccessTokenLog(
            session_id=self.session_id,
            scope=AuthorizationScope.model_validate_json(self.scope),
            header=json.loads(self.header),
            claims=json.loads(self.claims),
            issued_at=self.issued_at,
        )


class IdpAuthorizationState(Base):
    __tablename__ = "idp_authorization_state"

    state_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    request_scope: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str] = mapped_column(TEXT)
    idp_slug: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    code_verifier: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_idp_authorization_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, state: schema.IdpAuthorizationState) -> Self:
        return cls(
            state_hash=state.state_hash,
            client_id=state.client_id,
            request_scope=state.request_scope.model_dump_json(exclude_none=True),
            request_state=state.request_state.model_dump_json(exclude_none=True),
            idp_slug=state.idp_slug,
            idp_issuer=state.idp_issuer,
            code_verifier=state.code_verifier,
            issued_at=to_timestamp(state.issued_at),
        )

    def to_schema(self) -> schema.IdpAuthorizationState:
        return schema.IdpAuthorizationState(
            state_hash=self.state_hash,
            client_id=self.client_id,
            request_scope=AuthorizationScope.model_validate_json(self.request_scope),
            request_state=AuthorizationState.model_validate_json(self.request_state),
            idp_slug=self.idp_slug,
            idp_issuer=self.idp_issuer,
            code_verifier=self.code_verifier,
            issued_at=self.issued_at,
        )


class IdpSession(Base):
    __tablename__ = "idp_session"

    client_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    user_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    idp_issuer: Mapped[str] = mapped_column(TEXT, primary_key=True)
    refresh_token_enc: Mapped[bytes] = mapped_column(BLOB)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    expires_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_idp_session_expires_at", expires_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, state: schema.IdpSession) -> Self:
        return cls(
            client_id=state.client_id,
            user_id=state.user_id,
            idp_issuer=state.idp_issuer,
            refresh_token_enc=state.refresh_token_enc,
            issued_at=to_timestamp(state.issued_at),
            expires_at=to_timestamp(state.expires_at),
        )

    def to_schema(self) -> schema.IdpSession:
        return schema.IdpSession(
            client_id=self.client_id,
            user_id=self.user_id,
            idp_issuer=self.idp_issuer,
            refresh_token_enc=self.refresh_token_enc,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
