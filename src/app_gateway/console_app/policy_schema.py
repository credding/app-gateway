from datetime import datetime

from pydantic import BaseModel

from app_gateway.console_app.app_schema import AppView, ResourcePolicyView
from app_gateway.console_app.catalog_schema import OwnerView
from app_gateway.policy import AccessRequestStatus, AccessType, ApprovalPolicy


class ListFilter(BaseModel):
    app_id: str | None = None
    resource_id: str | None = None
    resource_app_id: str | None = None


class ResourcePolicyFilter(BaseModel):
    resource_id: str | None = None
    resource_app_id: str | None = None


class ResourcePolicyCreate(BaseModel):
    resource_id: str
    access_type: AccessType
    approval: ApprovalPolicy


class ResourcePolicyUpdate(BaseModel):
    approval: ApprovalPolicy


class ListResourcePoliciesView(BaseModel):
    resource_policies: list[ResourcePolicyView]


class AccessResourceView(BaseModel):
    resource_id: str
    name: str
    uri: str


class AccessRequestCreate(BaseModel):
    app_id: str
    resource_id: str
    access_type: AccessType


class AccessRequestView(BaseModel):
    request_id: str
    access_type: AccessType
    status: AccessRequestStatus
    app: AppView
    resource_app: AppView
    resource: AccessResourceView
    requested_by: OwnerView
    decided_by: OwnerView | None
    decided_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ListAccessRequestsView(BaseModel):
    access_requests: list[AccessRequestView]


class AccessGrantCreate(BaseModel):
    app_id: str
    resource_id: str
    access_type: AccessType


class AccessGrantView(BaseModel):
    rule_id: str
    access_type: AccessType
    app: AppView
    resource_app: AppView
    resource: AccessResourceView
    created_at: datetime
    updated_at: datetime


class ListAccessGrantsView(BaseModel):
    access_grants: list[AccessGrantView]
