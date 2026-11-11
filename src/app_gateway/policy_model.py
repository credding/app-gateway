import json
from datetime import UTC, datetime
from typing import cast

from specified import exceptional, pure
from sqlalchemy import ForeignKey, Index
from sqlalchemy.dialects.sqlite import BLOB, INTEGER, TEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app_gateway import policy_schema as schema


@exceptional
class InvalidPolicyRecordError(ValueError):
    pass


@pure
def _to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


class Base(DeclarativeBase):
    pass


class IdentityProvider(Base):
    __tablename__ = "identity_provider"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    issuer: Mapped[str] = mapped_column(TEXT)
    alias: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    authorization_endpoint: Mapped[str] = mapped_column(TEXT)
    token_endpoint: Mapped[str] = mapped_column(TEXT)
    userinfo_endpoint: Mapped[str] = mapped_column(TEXT)
    userinfo_claims_map: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("uq_identity_provider_issuer", issuer, unique=True),
        Index("uq_identity_provider_alias", alias, unique=True),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.IdentityProvider:
        return schema.IdentityProvider(
            issuer=self.issuer,
            alias=self.alias,
            name=self.name,
            authorization_endpoint=self.authorization_endpoint,
            token_endpoint=self.token_endpoint,
            userinfo_endpoint=self.userinfo_endpoint,
            userinfo_claims_map=json.loads(self.userinfo_claims_map),
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class User(Base):
    __tablename__ = "user"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    user_id: Mapped[str] = mapped_column(TEXT, unique=True)
    claims: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = ({"sqlite_strict": True},)

    @pure
    def to_schema(self) -> schema.User:
        return schema.User(
            user_id=self.user_id,
            claims=json.loads(self.claims),
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class UserIdentity(Base):
    __tablename__ = "user_identity"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    user_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("user.join_key", ondelete="CASCADE")
    )
    idp_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("identity_provider.join_key", ondelete="RESTRICT")
    )
    idp_subject: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    user: Mapped[User] = relationship(lazy="raise")
    identity_provider: Mapped[IdentityProvider] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_user_identity_idp_idp_subject", idp_key, idp_subject, unique=True),
        Index("ix_user_identity_user", user_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.UserIdentity:
        return schema.UserIdentity(
            user_id=self.user.user_id,
            idp_issuer=self.identity_provider.issuer,
            idp_subject=self.idp_subject,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class App(Base):
    __tablename__ = "app"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    slug: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    identity_providers: Mapped[list[AppIdentityProvider]] = relationship(
        back_populates="app"
    )

    __table_args__ = (
        Index("uq_app_slug", slug, unique=True),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.App:
        return schema.App(
            slug=self.slug,
            name=self.name,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class AppOwner(Base):
    __tablename__ = "app_owner"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("app.join_key", ondelete="CASCADE")
    )
    user_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("user.join_key", ondelete="RESTRICT")
    )
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(lazy="raise")
    user: Mapped[User] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_app_owner_app_user", app_key, user_key, unique=True),
        Index("ix_app_owner_user", user_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.AppOwner:
        return schema.AppOwner(
            app_slug=self.app.slug,
            user_id=self.user.user_id,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class AppIdentityProvider(Base):
    __tablename__ = "app_identity_provider"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("app.join_key", ondelete="CASCADE")
    )
    idp_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("identity_provider.join_key", ondelete="RESTRICT")
    )
    client_id: Mapped[str] = mapped_column(TEXT)
    client_secret_enc: Mapped[bytes] = mapped_column(BLOB)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="identity_providers", lazy="raise")
    identity_provider: Mapped[IdentityProvider] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_app_identity_provider_app_idp", app_key, idp_key, unique=True),
        Index("ix_app_identity_provider_idp", idp_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.AppIdentityProvider:
        return schema.AppIdentityProvider(
            app_slug=self.app.slug,
            idp_issuer=self.identity_provider.issuer,
            client_id=self.client_id,
            client_secret_enc=self.client_secret_enc,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class Client(Base):
    __tablename__ = "client"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("app.join_key", ondelete="CASCADE")
    )
    client_type: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    client_id: Mapped[str] = mapped_column(TEXT, unique=True)
    client_secret_hash: Mapped[bytes | None] = mapped_column(BLOB)
    redirect_uris: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(lazy="raise")

    __table_args__ = (
        Index("ix_client_app", app_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.Client:
        client_type = schema.ClientType(self.client_type)

        match client_type:
            case schema.ClientType.CONFIDENTIAL:
                return schema.ConfidentialClient(
                    name=self.name,
                    app_slug=self.app.slug,
                    client_id=self.client_id,
                    client_secret_hash=cast("bytes", self.client_secret_hash),
                    redirect_uris=json.loads(self.redirect_uris),
                    created_at=_to_datetime(self.created_at),
                    updated_at=_to_datetime(self.updated_at),
                )
            case schema.ClientType.PUBLIC:
                return schema.PublicClient(
                    name=self.name,
                    app_slug=self.app.slug,
                    client_id=self.client_id,
                    redirect_uris=json.loads(self.redirect_uris),
                    created_at=_to_datetime(self.created_at),
                    updated_at=_to_datetime(self.updated_at),
                )


class Resource(Base):
    __tablename__ = "resource"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("app.join_key", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(TEXT)
    uri: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_resource_uri", uri, unique=True),
        Index("ix_resource_app", app_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.Resource:
        return schema.Resource(
            name=self.name,
            uri=self.uri,
            app_slug=self.app.slug,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )


class AppAccessRule(Base):
    __tablename__ = "client_access_rule"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("app.join_key", ondelete="CASCADE")
    )
    resource_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey("resource.join_key", ondelete="CASCADE")
    )
    access_type: Mapped[str] = mapped_column(TEXT)
    policy: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(lazy="raise")
    resource: Mapped[Resource] = relationship(lazy="raise")

    __table_args__ = (
        Index(
            "uq_client_access_rule_client_app_resource_access_type",
            app_key,
            resource_key,
            access_type,
            unique=True,
        ),
        Index("ix_client_access_rule_resource", resource_key),
        {"sqlite_strict": True},
    )

    @pure
    def to_schema(self) -> schema.AppAccessRule:
        try:
            access_type = schema.AccessType(self.access_type)
        except ValueError as e:
            raise InvalidPolicyRecordError from e

        return schema.AppAccessRule(
            app_slug=self.app.slug,
            resource_uri=self.resource.uri,
            access_type=access_type,
            created_at=_to_datetime(self.created_at),
            updated_at=_to_datetime(self.updated_at),
        )
