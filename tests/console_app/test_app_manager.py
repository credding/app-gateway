from app_gateway.common.clock import to_datetime
from app_gateway.console_app.app_manager import (
    idp_redirect_uri,
    idp_view,
    resource_view,
)
from app_gateway.db import policy_model as model
from app_gateway.policy import AccessType, ApprovalPolicy

TIME = 1_800_000_000


def _resource(access_policies: list[model.ResourceAccessPolicy]) -> model.Resource:
    return model.Resource(
        resource_id="res_123",
        name="Files",
        uri="https://files.example.com",
        access_policies=access_policies,
        created_at=TIME,
        updated_at=TIME + 1,
    )


def _policy(
    access_type: AccessType, approval: ApprovalPolicy
) -> model.ResourceAccessPolicy:
    return model.ResourceAccessPolicy(
        policy_id=f"pol_{access_type.value}",
        access_type=access_type.value,
        approval=approval.value,
        created_at=TIME,
        updated_at=TIME + 2,
    )


def test_resource_view_without_access_policies() -> None:
    view = resource_view(_resource([]))

    assert view.resource_id == "res_123"
    assert view.name == "Files"
    assert view.uri == "https://files.example.com"
    assert view.access_policies == []
    assert view.created_at == to_datetime(TIME)
    assert view.updated_at == to_datetime(TIME + 1)


def test_resource_view_maps_and_sorts_access_policies() -> None:
    view = resource_view(
        _resource(
            [
                _policy(AccessType.PUBLIC, ApprovalPolicy.AUTO_APPROVE),
                _policy(AccessType.AUTHENTICATED, ApprovalPolicy.REQUIRE_APPROVAL),
            ]
        )
    )

    assert [
        (policy.access_type, policy.approval) for policy in view.access_policies
    ] == [
        (AccessType.AUTHENTICATED, ApprovalPolicy.REQUIRE_APPROVAL),
        (AccessType.PUBLIC, ApprovalPolicy.AUTO_APPROVE),
    ]
    assert view.access_policies[0].policy_id == "pol_authenticated"
    assert view.access_policies[0].resource_id == "res_123"
    assert view.access_policies[0].access_type is AccessType.AUTHENTICATED
    assert view.access_policies[0].approval is ApprovalPolicy.REQUIRE_APPROVAL
    assert view.access_policies[0].created_at == to_datetime(TIME)
    assert view.access_policies[0].updated_at == to_datetime(TIME + 2)


def _idp() -> model.IdentityProvider:
    return model.IdentityProvider(idp_id="idp_123", slug="github", name="GitHub")


def test_idp_redirect_uri() -> None:
    assert (
        idp_redirect_uri("https://id.example.com", "github")
        == "https://id.example.com/oauth/broker/github/callback"
    )


def test_idp_redirect_uri_strips_trailing_slash() -> None:
    assert (
        idp_redirect_uri("https://id.example.com/", "github")
        == "https://id.example.com/oauth/broker/github/callback"
    )


def test_idp_view_includes_redirect_uri() -> None:
    view = idp_view(_idp(), "https://id.example.com")

    assert view.idp_id == "idp_123"
    assert view.name == "GitHub"
    assert view.redirect_uri == "https://id.example.com/oauth/broker/github/callback"
