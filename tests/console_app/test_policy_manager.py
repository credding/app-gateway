from app_gateway.common.clock import to_datetime
from app_gateway.console_app.policy_manager import (
    access_grant_view,
    access_request_view,
)
from app_gateway.db import policy_model as model
from app_gateway.policy import AccessRequestStatus, AccessType

TIME = 1_800_000_000


def _app(app_id: str, slug: str) -> model.App:
    return model.App(app_id=app_id, slug=slug, name=slug.title())


def _resource() -> model.Resource:
    return model.Resource(
        resource_id="res_123",
        name="Files",
        uri="https://files.example.com",
        app=_app("app_owner", "files"),
    )


def _user(user_id: str, name: str) -> model.User:
    return model.User(user_id=user_id, claims=f'{{"name": "{name}", "email": "x"}}')


def _request(
    status: AccessRequestStatus,
    decided_by: model.User | None,
    decided_at: int | None,
) -> model.AppAccessRequest:
    return model.AppAccessRequest(
        request_id="areq_123",
        app=_app("app_requester", "client"),
        resource=_resource(),
        access_type=AccessType.DELEGATED.value,
        status=status.value,
        requested_by=_user("sub_requester", "Requester"),
        decided_by=decided_by,
        decided_at=decided_at,
        created_at=TIME,
        updated_at=TIME + 1,
    )


def test_access_request_view_pending() -> None:
    view = access_request_view(_request(AccessRequestStatus.PENDING, None, None))

    assert view.request_id == "areq_123"
    assert view.access_type is AccessType.DELEGATED
    assert view.status is AccessRequestStatus.PENDING
    assert view.app.app_id == "app_requester"
    assert view.resource_app.app_id == "app_owner"
    assert view.resource.resource_id == "res_123"
    assert view.resource.uri == "https://files.example.com"
    assert view.requested_by.user_id == "sub_requester"
    assert view.requested_by.name == "Requester"
    assert view.decided_by is None
    assert view.decided_at is None
    assert view.created_at == to_datetime(TIME)
    assert view.updated_at == to_datetime(TIME + 1)


def test_access_request_view_decided_by_owner() -> None:
    view = access_request_view(
        _request(AccessRequestStatus.APPROVED, _user("sub_owner", "Owner"), TIME + 5)
    )

    assert view.status is AccessRequestStatus.APPROVED
    assert view.decided_by is not None
    assert view.decided_by.user_id == "sub_owner"
    assert view.decided_at == to_datetime(TIME + 5)


def test_access_request_view_auto_approved_has_no_decider() -> None:
    view = access_request_view(_request(AccessRequestStatus.APPROVED, None, TIME))

    assert view.status is AccessRequestStatus.APPROVED
    assert view.decided_by is None
    assert view.decided_at == to_datetime(TIME)


def test_access_request_view_exposes_only_display_claims() -> None:
    view = access_request_view(_request(AccessRequestStatus.PENDING, None, None))

    assert "email" not in view.requested_by.model_dump()


def test_access_grant_view() -> None:
    view = access_grant_view(
        model.AppAccessRule(
            rule_id="rule_123",
            app=_app("app_requester", "client"),
            resource=_resource(),
            access_type=AccessType.AUTHENTICATED.value,
            created_at=TIME,
            updated_at=TIME + 1,
        )
    )

    assert view.rule_id == "rule_123"
    assert view.access_type is AccessType.AUTHENTICATED
    assert view.app.app_id == "app_requester"
    assert view.resource_app.app_id == "app_owner"
    assert view.resource.resource_id == "res_123"
    assert view.created_at == to_datetime(TIME)
    assert view.updated_at == to_datetime(TIME + 1)
