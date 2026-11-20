from app_gateway.common.clock import to_datetime
from app_gateway.db import policy_model as model
from app_gateway.policy import AccessRequestStatus, AccessType, ApprovalPolicy

TIME = 1_800_000_000


def test_resource_access_policy_to_schema() -> None:
    policy = model.ResourceAccessPolicy(
        policy_id="pol_123",
        resource=model.Resource(resource_id="res_123"),
        access_type=AccessType.DELEGATED.value,
        approval=ApprovalPolicy.REQUIRE_APPROVAL.value,
        created_at=TIME,
        updated_at=TIME + 1,
    )

    result = policy.to_schema()

    assert result.policy_id == "pol_123"
    assert result.resource_id == "res_123"
    assert result.access_type is AccessType.DELEGATED
    assert result.approval is ApprovalPolicy.REQUIRE_APPROVAL
    assert result.created_at == to_datetime(TIME)
    assert result.updated_at == to_datetime(TIME + 1)


def test_app_access_request_to_schema() -> None:
    request = model.AppAccessRequest(
        request_id="areq_123",
        app=model.App(app_id="app_123"),
        resource=model.Resource(resource_id="res_123"),
        access_type=AccessType.AUTHENTICATED.value,
        status=AccessRequestStatus.APPROVED.value,
        requested_by=model.User(user_id="sub_requester"),
        decided_by=model.User(user_id="sub_owner"),
        decided_at=TIME + 2,
        created_at=TIME,
        updated_at=TIME + 1,
    )

    result = request.to_schema()

    assert result.request_id == "areq_123"
    assert result.app_id == "app_123"
    assert result.resource_id == "res_123"
    assert result.access_type is AccessType.AUTHENTICATED
    assert result.status is AccessRequestStatus.APPROVED
    assert result.requested_by_user_id == "sub_requester"
    assert result.decided_by_user_id == "sub_owner"
    assert result.decided_at == to_datetime(TIME + 2)


def test_app_access_request_to_schema_undecided() -> None:
    request = model.AppAccessRequest(
        request_id="areq_123",
        app=model.App(app_id="app_123"),
        resource=model.Resource(resource_id="res_123"),
        access_type=AccessType.AUTHENTICATED.value,
        status=AccessRequestStatus.PENDING.value,
        requested_by=model.User(user_id="sub_requester"),
        decided_by=None,
        decided_at=None,
        created_at=TIME,
        updated_at=TIME,
    )

    result = request.to_schema()

    assert result.decided_by_user_id is None
    assert result.decided_at is None


def test_app_access_rule_to_schema() -> None:
    rule = model.AppAccessRule(
        rule_id="rule_123",
        app=model.App(app_id="app_123"),
        resource=model.Resource(resource_id="res_123"),
        access_type=AccessType.AUTHENTICATED.value,
        created_at=TIME,
        updated_at=TIME + 1,
    )

    result = rule.to_schema()

    assert result.rule_id == "rule_123"
    assert result.app_id == "app_123"
    assert result.resource_id == "res_123"
    assert result.access_type is AccessType.AUTHENTICATED
    assert result.created_at == to_datetime(TIME)
    assert result.updated_at == to_datetime(TIME + 1)
