import json
from typing import assert_never, cast

from sqlalchemy import ForeignKey, Index, text
from sqlalchemy.dialects.sqlite import BLOB, INTEGER, TEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app_gateway.policy import schema


class Base(DeclarativeBase):
    pass


class IdentityProvider(Base):
    __tablename__ = "identity_provider"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    idp_id: Mapped[str] = mapped_column(TEXT, unique=True)
    issuer: Mapped[str] = mapped_column(TEXT)
    slug: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    authorization_endpoint: Mapped[str] = mapped_column(TEXT)
    token_endpoint: Mapped[str] = mapped_column(TEXT)
    userinfo_endpoint: Mapped[str] = mapped_column(TEXT)
    userinfo_claims_map: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    __table_args__ = (
        Index("uq_identity_provider_issuer", issuer, unique=True),
        Index("uq_identity_provider_slug", slug, unique=True),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.IdentityProvider:
        return schema.IdentityProvider(
            idp_id=self.idp_id,
            issuer=self.issuer,
            slug=self.slug,
            name=self.name,
            authorization_endpoint=self.authorization_endpoint,
            token_endpoint=self.token_endpoint,
            userinfo_endpoint=self.userinfo_endpoint,
            userinfo_claims_map=json.loads(self.userinfo_claims_map),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class User(Base):
    __tablename__ = "user"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    user_id: Mapped[str] = mapped_column(TEXT, unique=True)
    claims: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    identities: Mapped[list[UserIdentity]] = relationship(
        back_populates="user", lazy="raise"
    )
    owned_apps: Mapped[list[AppOwner]] = relationship(
        back_populates="user", lazy="raise"
    )

    __table_args__ = ({"sqlite_strict": True},)

    def to_schema(self) -> schema.User:
        return schema.User(
            user_id=self.user_id,
            claims=json.loads(self.claims),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class UserIdentity(Base):
    __tablename__ = "user_identity"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    user_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(User.join_key, ondelete="CASCADE")
    )
    idp_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(IdentityProvider.join_key, ondelete="RESTRICT")
    )
    idp_subject: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    user: Mapped[User] = relationship(lazy="raise")
    idp: Mapped[IdentityProvider] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_user_identity_idp_idp_subject", idp_key, idp_subject, unique=True),
        Index("ix_user_identity_user", user_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.UserIdentity:
        return schema.UserIdentity(
            user_id=self.user.user_id,
            idp_id=self.idp.idp_id,
            idp_subject=self.idp_subject,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class App(Base):
    __tablename__ = "app"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_id: Mapped[str] = mapped_column(TEXT, unique=True)
    slug: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    owners: Mapped[list[AppOwner]] = relationship(back_populates="app", lazy="raise")
    idps: Mapped[list[AppIdentityProvider]] = relationship(
        back_populates="app", lazy="raise"
    )
    clients: Mapped[list[Client]] = relationship(back_populates="app", lazy="raise")
    resources: Mapped[list[Resource]] = relationship(back_populates="app", lazy="raise")
    access_rules: Mapped[list[AppAccessRule]] = relationship(
        back_populates="app", lazy="raise"
    )
    access_requests: Mapped[list[AppAccessRequest]] = relationship(
        back_populates="app", lazy="raise"
    )

    __table_args__ = (
        Index("uq_app_slug", slug, unique=True),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.App:
        return schema.App(
            app_id=self.app_id,
            slug=self.slug,
            name=self.name,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class AppOwner(Base):
    __tablename__ = "app_owner"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    user_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(User.join_key, ondelete="RESTRICT")
    )
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="owners", lazy="raise")
    user: Mapped[User] = relationship(back_populates="owned_apps", lazy="raise")

    __table_args__ = (
        Index("uq_app_owner_app_user", app_key, user_key, unique=True),
        Index("ix_app_owner_user", user_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.AppOwner:
        return schema.AppOwner(
            app_id=self.app.app_id,
            user_id=self.user.user_id,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class AppIdentityProvider(Base):
    __tablename__ = "app_identity_provider"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    idp_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(IdentityProvider.join_key, ondelete="RESTRICT")
    )
    client_id: Mapped[str] = mapped_column(TEXT)
    client_secret_enc: Mapped[bytes] = mapped_column(BLOB)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="idps", lazy="raise")
    idp: Mapped[IdentityProvider] = relationship(lazy="raise")

    __table_args__ = (
        Index("uq_app_identity_provider_app_idp", app_key, idp_key, unique=True),
        Index("ix_app_identity_provider_idp", idp_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.AppIdentityProvider:
        return schema.AppIdentityProvider(
            app_id=self.app.app_id,
            idp_id=self.idp.idp_id,
            client_id=self.client_id,
            client_secret_enc=self.client_secret_enc,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class Client(Base):
    __tablename__ = "client"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    client_type: Mapped[str] = mapped_column(TEXT)
    name: Mapped[str] = mapped_column(TEXT)
    client_id: Mapped[str] = mapped_column(TEXT, unique=True)
    client_secret_hash: Mapped[bytes | None] = mapped_column(BLOB)
    redirect_uris: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="clients", lazy="raise")

    __table_args__ = (
        Index("ix_client_app", app_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.Client:
        client_type = schema.ClientType(self.client_type)
        match client_type:
            case schema.ClientType.CONFIDENTIAL:
                return schema.ConfidentialClient(
                    client_type=client_type,
                    name=self.name,
                    app_id=self.app.app_id,
                    client_id=self.client_id,
                    client_secret_hash=cast("bytes", self.client_secret_hash),
                    redirect_uris=json.loads(self.redirect_uris),
                    created_at=self.created_at,
                    updated_at=self.updated_at,
                )
            case schema.ClientType.PUBLIC:
                return schema.PublicClient(
                    client_type=client_type,
                    name=self.name,
                    app_id=self.app.app_id,
                    client_id=self.client_id,
                    redirect_uris=json.loads(self.redirect_uris),
                    created_at=self.created_at,
                    updated_at=self.updated_at,
                )
            case unreachable:
                assert_never(unreachable)


class Resource(Base):
    __tablename__ = "resource"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    resource_id: Mapped[str] = mapped_column(TEXT, unique=True)
    name: Mapped[str] = mapped_column(TEXT)
    uri: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="resources", lazy="raise")
    access_rules: Mapped[list[AppAccessRule]] = relationship(
        back_populates="resource", lazy="raise"
    )
    access_policies: Mapped[list[ResourceAccessPolicy]] = relationship(
        back_populates="resource", lazy="raise"
    )
    access_requests: Mapped[list[AppAccessRequest]] = relationship(
        back_populates="resource", lazy="raise"
    )

    __table_args__ = (
        Index("uq_resource_uri", uri, unique=True),
        Index("ix_resource_app", app_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.Resource:
        return schema.Resource(
            resource_id=self.resource_id,
            app_id=self.app.app_id,
            name=self.name,
            uri=self.uri,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class AppAccessRule(Base):
    __tablename__ = "app_access_rule"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    rule_id: Mapped[str] = mapped_column(TEXT)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    resource_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(Resource.join_key, ondelete="CASCADE")
    )
    access_type: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="access_rules", lazy="raise")
    resource: Mapped[Resource] = relationship(
        back_populates="access_rules", lazy="raise"
    )

    __table_args__ = (
        Index(
            "uq_app_access_rule_app_resource_access_type",
            app_key,
            resource_key,
            access_type,
            unique=True,
        ),
        Index("ix_app_access_rule_resource", resource_key),
        Index("uq_app_access_rule_rule_id", rule_id, unique=True),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.AppAccessRule:
        return schema.AppAccessRule(
            rule_id=self.rule_id,
            app_id=self.app.app_id,
            resource_id=self.resource.resource_id,
            access_type=schema.AccessType(self.access_type),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class ResourceAccessPolicy(Base):
    __tablename__ = "resource_access_policy"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    policy_id: Mapped[str] = mapped_column(TEXT, unique=True)
    resource_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(Resource.join_key, ondelete="CASCADE")
    )
    access_type: Mapped[str] = mapped_column(TEXT)
    approval: Mapped[str] = mapped_column(TEXT)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    resource: Mapped[Resource] = relationship(
        back_populates="access_policies", lazy="raise"
    )

    __table_args__ = (
        Index(
            "uq_resource_access_policy_resource_access_type",
            resource_key,
            access_type,
            unique=True,
        ),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.ResourceAccessPolicy:
        return schema.ResourceAccessPolicy(
            policy_id=self.policy_id,
            resource_id=self.resource.resource_id,
            access_type=schema.AccessType(self.access_type),
            approval=schema.ApprovalPolicy(self.approval),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class AppAccessRequest(Base):
    __tablename__ = "app_access_request"

    join_key: Mapped[int] = mapped_column(INTEGER, primary_key=True)
    request_id: Mapped[str] = mapped_column(TEXT, unique=True)
    app_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(App.join_key, ondelete="CASCADE")
    )
    resource_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(Resource.join_key, ondelete="CASCADE")
    )
    access_type: Mapped[str] = mapped_column(TEXT)
    status: Mapped[str] = mapped_column(TEXT)
    requested_by_user_key: Mapped[int] = mapped_column(
        INTEGER, ForeignKey(User.join_key, ondelete="RESTRICT")
    )
    decided_by_user_key: Mapped[int | None] = mapped_column(
        INTEGER, ForeignKey(User.join_key, ondelete="RESTRICT")
    )
    decided_at: Mapped[int | None] = mapped_column(INTEGER)
    created_at: Mapped[int] = mapped_column(INTEGER)
    updated_at: Mapped[int] = mapped_column(INTEGER)

    app: Mapped[App] = relationship(back_populates="access_requests", lazy="raise")
    resource: Mapped[Resource] = relationship(
        back_populates="access_requests", lazy="raise"
    )
    requested_by: Mapped[User] = relationship(
        foreign_keys=[requested_by_user_key], lazy="raise"
    )
    decided_by: Mapped[User | None] = relationship(
        foreign_keys=[decided_by_user_key], lazy="raise"
    )

    __table_args__ = (
        Index(
            "uq_app_access_request_pending",
            app_key,
            resource_key,
            access_type,
            unique=True,
            sqlite_where=text("status = 'pending'"),
        ),
        Index("ix_app_access_request_app", app_key),
        Index("ix_app_access_request_resource", resource_key),
        {"sqlite_strict": True},
    )

    def to_schema(self) -> schema.AppAccessRequest:
        return schema.AppAccessRequest(
            request_id=self.request_id,
            app_id=self.app.app_id,
            resource_id=self.resource.resource_id,
            access_type=schema.AccessType(self.access_type),
            status=schema.AccessRequestStatus(self.status),
            requested_by_user_id=self.requested_by.user_id,
            decided_by_user_id=(
                self.decided_by.user_id if self.decided_by is not None else None
            ),
            decided_at=self.decided_at,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
