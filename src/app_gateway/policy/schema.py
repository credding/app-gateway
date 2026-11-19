import enum
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, TypeAdapter


class _TimestampMixin:
    created_at: datetime
    updated_at: datetime


class IdentityProvider(_TimestampMixin, BaseModel):
    idp_id: str
    issuer: str
    slug: str
    name: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    userinfo_claims_map: dict[str, str]


class User(_TimestampMixin, BaseModel):
    user_id: str
    claims: dict[str, Any]


class UserIdentity(_TimestampMixin, BaseModel):
    user_id: str
    idp_id: str
    idp_subject: str


class App(_TimestampMixin, BaseModel):
    app_id: str
    slug: str
    name: str


class AppOwner(_TimestampMixin, BaseModel):
    app_id: str
    user_id: str


class AppIdentityProvider(_TimestampMixin, BaseModel):
    app_id: str
    idp_id: str
    client_id: str
    client_secret_enc: bytes


class ClientType(enum.StrEnum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class _Client[K: ClientType](_TimestampMixin, BaseModel):
    client_type: K
    name: str
    app_id: str
    client_id: str
    redirect_uris: list[str]


class ConfidentialClient(_Client[Literal[ClientType.CONFIDENTIAL]]):
    client_secret_hash: bytes


class PublicClient(_Client[Literal[ClientType.PUBLIC]]):
    pass


type Client = Annotated[
    ConfidentialClient | PublicClient,
    Field(discriminator="client_type"),
]

ClientTypeAdapter = TypeAdapter(Client)


class Resource(_TimestampMixin, BaseModel):
    app_id: str
    resource_id: str
    name: str
    uri: str


class AccessType(enum.StrEnum):
    AUTHENTICATED = "authenticated"
    AUTONOMOUS = "autonomous"
    DELEGATED = "delegated"
    PUBLIC = "public"


class AppAccessRule(_TimestampMixin, BaseModel):
    app_id: str
    resource_id: str
    access_type: AccessType
