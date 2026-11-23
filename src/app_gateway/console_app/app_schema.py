from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

from app_gateway.policy import AccessType, ApprovalPolicy, ClientType

type Slug = Annotated[str, Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=64)]
type Name = Annotated[str, Field(min_length=1, max_length=200)]
type NonEmpty = Annotated[str, Field(min_length=1)]


class IdpView(BaseModel):
    idp_id: str
    name: str
    redirect_uri: str


class ListIdpsView(BaseModel):
    identity_providers: list[IdpView]


class UserView(BaseModel):
    user_id: str
    claims: dict[str, Any]


class ListAppsView(BaseModel):
    apps: list[ListAppsItem]


class ListAppsItem(BaseModel):
    app_id: str
    slug: str
    name: str
    owners: list[UserView]
    idps: list[AppIdpView]
    clients: list[ClientView]
    resources: list[ResourceView]
    created_at: datetime
    updated_at: datetime


class AppView(BaseModel):
    app_id: str
    slug: str
    name: str


class AppCreate(BaseModel):
    slug: Slug
    name: Name


class AppUpdate(BaseModel):
    slug: Slug | None = None
    name: Name | None = None


class AppIdpView(BaseModel):
    idp_id: str
    name: str
    client_id: str


class AppIdpUpdate(BaseModel):
    client_id: NonEmpty
    client_secret: NonEmpty


class ClientView(BaseModel):
    client_type: ClientType
    name: str
    client_id: str
    redirect_uris: list[str]
    created_at: datetime
    updated_at: datetime


class ClientSecretView(ClientView):
    client_secret: str | None


class ClientCreate(BaseModel):
    client_type: ClientType
    name: Name
    redirect_uris: list[str]


class ClientUpdate(BaseModel):
    name: Name | None = None
    redirect_uris: list[str] | None = None


class ResourceView(BaseModel):
    resource_id: str
    name: str
    uri: str
    access_policies: list[ResourcePolicyView]
    created_at: datetime
    updated_at: datetime


class ResourceCreate(BaseModel):
    name: Name
    uri: NonEmpty


class ResourceUpdate(BaseModel):
    name: Name | None = None
    uri: NonEmpty | None = None


class ResourcePolicyView(BaseModel):
    policy_id: str
    resource_id: str
    access_type: AccessType
    approval: ApprovalPolicy
    created_at: datetime
    updated_at: datetime
