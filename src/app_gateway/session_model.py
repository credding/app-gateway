from sqlalchemy import Index
from sqlalchemy.dialects.sqlite import BLOB, INTEGER, TEXT
from sqlalchemy.orm import Mapped, mapped_column

from app_gateway.policy_model import Base


class IdpAuthorizationState(Base):
    __tablename__ = "idp_authorization_state"

    state_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    request: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    idp_code_verifier: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_idp_authorization_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )


class AuthorizationCodeState(Base):
    __tablename__ = "authorization_code_state"

    code_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    client_id: Mapped[str] = mapped_column(TEXT)
    user_id: Mapped[str] = mapped_column(TEXT)
    request: Mapped[str] = mapped_column(TEXT)
    request_state: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    invalidated_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_authorization_code_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )


class RefreshTokenState(Base):
    __tablename__ = "refresh_token_state"

    refresh_token_hash: Mapped[bytes] = mapped_column(BLOB, primary_key=True)
    code_hash: Mapped[bytes] = mapped_column(BLOB)
    client_id: Mapped[str] = mapped_column(TEXT)
    user_id: Mapped[str] = mapped_column(TEXT)
    request: Mapped[str] = mapped_column(TEXT)
    idp_issuer: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)
    invalidated_at: Mapped[int | None] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_refresh_token_state_code", code_hash),
        Index("ix_refresh_token_state_issued_at", issued_at),
        {"sqlite_strict": True},
    )


class IdpSession(Base):
    __tablename__ = "idp_session"

    client_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    user_id: Mapped[str] = mapped_column(TEXT, primary_key=True)
    idp_issuer: Mapped[str] = mapped_column(TEXT, primary_key=True)
    idp_session_enc: Mapped[bytes] = mapped_column(BLOB)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("ix_idp_session_issued_at", issued_at),
        {"sqlite_strict": True},
    )


class AccessTokenLog(Base):
    __tablename__ = "access_token_log"

    rowid: Mapped[int] = mapped_column(INTEGER, system=True)
    request: Mapped[str] = mapped_column(TEXT)
    header: Mapped[str] = mapped_column(TEXT)
    claims: Mapped[str] = mapped_column(TEXT)
    issued_at: Mapped[int] = mapped_column(INTEGER)

    __mapper_args__ = {"primary_key": [rowid]}  # noqa: RUF012

    __table_args__ = (
        Index("ix_access_token_log_issued_at", issued_at),
        {"sqlite_strict": True},
    )
