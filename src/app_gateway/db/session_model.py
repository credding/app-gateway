import json
from typing import Self

from sqlalchemy import FetchedValue, Index
from sqlalchemy.dialects.sqlite import BLOB, INTEGER, TEXT
from sqlalchemy.orm import Mapped, mapped_column

from app_gateway.common.clock import to_seconds, to_timestamp
from app_gateway.db.policy_model import Base
from app_gateway.session import schema


class IdpAuthorizationState(Base):
    __tablename__ = "idp_authorization_state"

    state_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    request_scope: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    idp_code_verifier: Mapped[str] = mapped_column(TEXT)
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
            idp_issuer=state.idp_issuer,
            idp_code_verifier=state.idp_code_verifier,
            issued_at=to_timestamp(state.issued_at),
        )

    def to_schema(self) -> schema.IdpAuthorizationState:
        return schema.IdpAuthorizationState(
            state_hash=self.state_hash,
            client_id=self.client_id,
            request_scope=schema.AuthorizationRequestScope.model_validate_json(
                self.request_scope
            ),
            request_state=schema.AuthorizationRequestClientState.model_validate_json(
                self.request_state
            ),
            idp_issuer=self.idp_issuer,
            idp_code_verifier=self.idp_code_verifier,
            issued_at=self.issued_at,
        )


class AuthorizationCodeState(Base):
    __tablename__ = "authorization_code_state"

    code_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    user_id: Mapped[str] = mapped_column(TEXT)
    request_scope: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    invalidated_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_authorization_code_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, state: schema.AuthorizationCodeState) -> Self:
        return cls(
            code_hash=state.code_hash,
            client_id=state.client_id,
            user_id=state.user_id,
            request_scope=state.request_scope.model_dump_json(exclude_none=True),
            request_state=state.request_state.model_dump_json(exclude_none=True),
            idp_issuer=state.idp_issuer,
            issued_at=to_timestamp(state.issued_at),
            invalidated_at=to_timestamp(state.invalidated_at),
        )

    def to_schema(self) -> schema.AuthorizationCodeState:
        return schema.AuthorizationCodeState(
            code_hash=self.code_hash,
            client_id=self.client_id,
            user_id=self.user_id,
            request_scope=schema.AuthorizationRequestScope.model_validate_json(
                self.request_scope
            ),
            request_state=schema.AuthorizationRequestClientState.model_validate_json(
                self.request_state
            ),
            idp_issuer=self.idp_issuer,
            issued_at=self.issued_at,
            invalidated_at=self.invalidated_at,
        )


class RefreshTokenState(Base):
    __tablename__ = "refresh_token_state"

    refresh_token_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    code_hash: Mapped[bytes] = mapped_column(BLOB)
    client_id: Mapped[str] = mapped_column(TEXT)
    user_id: Mapped[str] = mapped_column(TEXT)
    request_scope: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    invalidated_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_refresh_token_state_code", code_hash),
        Index("ix_refresh_token_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, state: schema.RefreshTokenState) -> Self:
        return cls(
            refresh_token_hash=state.refresh_token_hash,
            code_hash=state.code_hash,
            client_id=state.client_id,
            user_id=state.user_id,
            request_scope=state.request_scope.model_dump_json(exclude_none=True),
            idp_issuer=state.idp_issuer,
            issued_at=to_timestamp(state.issued_at),
            invalidated_at=to_timestamp(state.invalidated_at),
        )

    def to_schema(self) -> schema.RefreshTokenState:
        return schema.RefreshTokenState(
            refresh_token_hash=self.refresh_token_hash,
            code_hash=self.code_hash,
            client_id=self.client_id,
            user_id=self.user_id,
            request_scope=schema.AuthorizationRequestScope.model_validate_json(
                self.request_scope
            ),
            idp_issuer=self.idp_issuer,
            issued_at=self.issued_at,
            invalidated_at=self.invalidated_at,
        )


class IdpSession(Base):
    __tablename__ = "idp_session"

    client_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    user_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    idp_issuer: Mapped[str] = mapped_column(TEXT, primary_key=True)
    expires_in: Mapped[int | None] = mapped_column(INTEGER)
    refresh_token_enc: Mapped[bytes] = mapped_column(BLOB)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_idp_session_issued_at", issued_at),
        {"sqlite_strict": True},
    )

    @classmethod
    def from_schema(cls, state: schema.IdpSession) -> Self:
        return cls(
            client_id=state.client_id,
            user_id=state.user_id,
            idp_issuer=state.idp_issuer,
            expires_in=to_seconds(state.expires_in),
            refresh_token_enc=state.refresh_token_enc,
            issued_at=to_timestamp(state.issued_at),
        )

    def to_schema(self) -> schema.IdpSession:
        return schema.IdpSession(
            client_id=self.client_id,
            user_id=self.user_id,
            idp_issuer=self.idp_issuer,
            expires_in=self.expires_in,
            refresh_token_enc=self.refresh_token_enc,
            issued_at=self.issued_at,
        )


class AccessTokenLog(Base):
    __tablename__ = "access_token_log"

    rowid: Mapped[int] = mapped_column(
        INTEGER, system=True, server_default=FetchedValue()
    )
    request_scope: Mapped[str] = mapped_column(TEXT)
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
            request_scope=log.request_scope.model_dump_json(exclude_none=True),
            header=json.dumps(log.header),
            claims=json.dumps(log.claims),
            issued_at=to_timestamp(log.issued_at),
        )

    def to_schema(self) -> schema.AccessTokenLog:
        return schema.AccessTokenLog(
            request_scope=schema.AuthorizationRequestScope.model_validate_json(
                self.request_scope
            ),
            header=json.loads(self.header),
            claims=json.loads(self.claims),
            issued_at=self.issued_at,
        )
