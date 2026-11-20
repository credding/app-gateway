from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response

from app_gateway.console_app import policy_manager
from app_gateway.console_app.app_schema import ResourcePolicyView
from app_gateway.console_app.auth import UserId
from app_gateway.console_app.policy_schema import (
    AccessGrantCreate,
    AccessGrantView,
    AccessRequestCreate,
    AccessRequestView,
    ListAccessGrantsView,
    ListAccessRequestsView,
    ListFilter,
    ListResourcePoliciesView,
    ResourcePolicyCreate,
    ResourcePolicyFilter,
    ResourcePolicyUpdate,
)


def _no_store(response: Response) -> None:
    response.headers["cache-control"] = "no-store"


router = APIRouter(prefix="/api/policy", dependencies=[Depends(_no_store)])


@router.get("/resource-policies")
async def list_resource_policies(
    user_id: UserId,  # ruff: ignore[unused-function-argument]
    filters: Annotated[ResourcePolicyFilter, Query()],
) -> ListResourcePoliciesView:
    return ListResourcePoliciesView(
        resource_policies=await policy_manager.list_resource_policies(filters)
    )


@router.post("/resource-policies", status_code=201)
async def create_resource_policy(
    user_id: UserId, body: ResourcePolicyCreate
) -> ResourcePolicyView:
    return await policy_manager.create_resource_policy(user_id, body)


@router.patch("/resource-policies/{policy_id}")
async def update_resource_policy(
    user_id: UserId, policy_id: str, body: ResourcePolicyUpdate
) -> ResourcePolicyView:
    return await policy_manager.update_resource_policy(user_id, policy_id, body)


@router.delete("/resource-policies/{policy_id}", status_code=204)
async def delete_resource_policy(user_id: UserId, policy_id: str) -> Response:
    await policy_manager.delete_resource_policy(user_id, policy_id)
    return Response(status_code=204)


@router.get("/access-requests")
async def list_access_requests(
    user_id: UserId, filters: Annotated[ListFilter, Query()]
) -> ListAccessRequestsView:
    return ListAccessRequestsView(
        access_requests=await policy_manager.list_access_requests(user_id, filters)
    )


@router.post("/access-requests", status_code=201)
async def create_access_request(
    user_id: UserId, body: AccessRequestCreate
) -> AccessRequestView:
    return await policy_manager.create_access_request(user_id, body)


@router.get("/access-requests/{request_id}")
async def get_access_request(user_id: UserId, request_id: str) -> AccessRequestView:
    return await policy_manager.get_access_request(user_id, request_id)


@router.post("/access-requests/{request_id}/cancel")
async def cancel_access_request(user_id: UserId, request_id: str) -> AccessRequestView:
    return await policy_manager.cancel_access_request(user_id, request_id)


@router.post("/access-requests/{request_id}/approve")
async def approve_access_request(user_id: UserId, request_id: str) -> AccessRequestView:
    return await policy_manager.approve_access_request(user_id, request_id)


@router.post("/access-requests/{request_id}/deny")
async def deny_access_request(user_id: UserId, request_id: str) -> AccessRequestView:
    return await policy_manager.deny_access_request(user_id, request_id)


@router.get("/access-grants")
async def list_access_grants(
    user_id: UserId, filters: Annotated[ListFilter, Query()]
) -> ListAccessGrantsView:
    return ListAccessGrantsView(
        access_grants=await policy_manager.list_access_grants(user_id, filters)
    )


@router.post("/access-grants", status_code=201)
async def create_access_grant(
    user_id: UserId, body: AccessGrantCreate
) -> AccessGrantView:
    return await policy_manager.create_access_grant(user_id, body)


@router.get("/access-grants/{rule_id}")
async def get_access_grant(user_id: UserId, rule_id: str) -> AccessGrantView:
    return await policy_manager.get_access_grant(user_id, rule_id)


@router.delete("/access-grants/{rule_id}", status_code=204)
async def delete_access_grant(user_id: UserId, rule_id: str) -> Response:
    await policy_manager.delete_access_grant(user_id, rule_id)
    return Response(status_code=204)
