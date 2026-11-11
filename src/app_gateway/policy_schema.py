import enum
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, TypeAdapter


class TimestampMixin:
    created_at: datetime | None = None
    updated_at: datetime | None = None


class IdentityProvider(TimestampMixin, BaseModel):
    issuer: str
    alias: str
    name: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    userinfo_claims_map: dict[str, str]


class User(TimestampMixin, BaseModel):
    user_id: str
    claims: dict[str, Any]


class UserIdentity(TimestampMixin, BaseModel):
    user_id: str
    idp_issuer: str
    idp_subject: str


class App(TimestampMixin, BaseModel):
    slug: str
    name: str


class AppOwner(TimestampMixin, BaseModel):
    app_slug: str
    user_id: str


class AppIdentityProvider(TimestampMixin, BaseModel):
    app_slug: str
    idp_issuer: str
    client_id: str
    client_secret_enc: bytes


class ClientType(enum.Enum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class ConfidentialClient(TimestampMixin, BaseModel):
    client_type: Literal[ClientType.CONFIDENTIAL] = ClientType.CONFIDENTIAL
    name: str
    app_slug: str
    client_id: str
    client_secret_hash: bytes
    redirect_uris: list[str]


class PublicClient(TimestampMixin, BaseModel):
    client_type: Literal[ClientType.PUBLIC] = ClientType.PUBLIC
    name: str
    app_slug: str
    client_id: str
    redirect_uris: list[str]


type Client = Annotated[
    ConfidentialClient | PublicClient,
    Field(discriminator="client_type"),
]

ClientAdapter = TypeAdapter(Client)


class Resource(TimestampMixin, BaseModel):
    name: str
    uri: str
    app_slug: str


class AccessType(enum.Enum):
    AUTHENTICATED = "authenticated"
    AUTONOMOUS = "autonomous"
    PUBLIC = "public"


class AppAccessRule(TimestampMixin, BaseModel):
    app_slug: str
    resource_uri: str
    access_type: AccessType


class ClientAccessRule(TimestampMixin, BaseModel):
    client_id: str
    resource_uri: str
