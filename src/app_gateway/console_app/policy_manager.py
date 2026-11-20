from fastapi import HTTPException
from sqlalchemy import ColumnElement, Select, delete, exists, select
from sqlalchemy.orm import InstrumentedAttribute, Session, selectinload

from app_gateway.common.clock import now, to_datetime, to_timestamp
from app_gateway.common.tokens import generate_id_token
from app_gateway.console_app.app_manager import (
    app_manager_error,
    app_not_found_error,
    app_view,
    get_owned_app,
    resource_not_found_error,
    resource_policy_view,
    user_not_found_error,
)
from app_gateway.console_app.app_schema import ResourcePolicyView
from app_gateway.console_app.catalog_manager import owner_view
from app_gateway.console_app.policy_schema import (
    AccessGrantCreate,
    AccessGrantView,
    AccessRequestCreate,
    AccessRequestView,
    AccessResourceView,
    ListFilter,
    ResourcePolicyCreate,
    ResourcePolicyFilter,
    ResourcePolicyUpdate,
)
from app_gateway.db import async_read, async_write
from app_gateway.db import policy_model as model
from app_gateway.policy import (
    AccessRequestStatus,
    AccessType,
    ApprovalPolicy,
)


def filter_required_error() -> HTTPException:
    return app_manager_error("app_id, resource_id or resource_app_id is required")


def resource_filter_required_error() -> HTTPException:
    return app_manager_error("resource_id or resource_app_id is required")


def resource_policy_not_found_error() -> HTTPException:
    return app_manager_error("access policy not found", 404)


def resource_policy_conflict_error() -> HTTPException:
    return app_manager_error("access policy already exists", 409)


def access_request_not_found_error() -> HTTPException:
    return app_manager_error("access request not found", 404)


def access_grant_not_found_error() -> HTTPException:
    return app_manager_error("access grant not found", 404)


def access_type_not_offered_error() -> HTTPException:
    return app_manager_error("access type not offered for this resource")


def access_already_granted_error() -> HTTPException:
    return app_manager_error("access already granted", 409)


def access_request_pending_error() -> HTTPException:
    return app_manager_error("access request already pending", 409)


def access_request_not_pending_error() -> HTTPException:
    return app_manager_error("access request is not pending", 409)


def _access_resource_view(resource: model.Resource) -> AccessResourceView:
    return AccessResourceView(
        resource_id=resource.resource_id, name=resource.name, uri=resource.uri
    )


def access_request_view(request: model.AppAccessRequest) -> AccessRequestView:
    return AccessRequestView(
        request_id=request.request_id,
        access_type=AccessType(request.access_type),
        status=AccessRequestStatus(request.status),
        app=app_view(request.app),
        resource_app=app_view(request.resource.app),
        resource=_access_resource_view(request.resource),
        requested_by=owner_view(request.requested_by),
        decided_by=(
            owner_view(request.decided_by) if request.decided_by is not None else None
        ),
        decided_at=(
            to_datetime(request.decided_at) if request.decided_at is not None else None
        ),
        created_at=to_datetime(request.created_at),
        updated_at=to_datetime(request.updated_at),
    )


def access_grant_view(rule: model.AppAccessRule) -> AccessGrantView:
    return AccessGrantView(
        rule_id=rule.rule_id,
        access_type=AccessType(rule.access_type),
        app=app_view(rule.app),
        resource_app=app_view(rule.resource.app),
        resource=_access_resource_view(rule.resource),
        created_at=to_datetime(rule.created_at),
        updated_at=to_datetime(rule.updated_at),
    )


def _owned_app_keys(sess: Session, user_id: str) -> set[int]:
    return set(
        sess.scalars(
            select(model.AppOwner.app_key)
            .join(model.AppOwner.user)
            .where(model.User.user_id == user_id)
        )
    )


def _get_user(sess: Session, user_id: str) -> model.User:
    user = sess.scalars(
        select(model.User).where(model.User.user_id == user_id)
    ).one_or_none()
    if user is None:
        raise user_not_found_error()
    return user


def _app_key(sess: Session, app_id: str) -> int | None:
    return sess.scalar(select(model.App.join_key).where(model.App.app_id == app_id))


def _resource_app_key(sess: Session, resource_id: str) -> int | None:
    return sess.scalar(
        select(model.Resource.app_key).where(model.Resource.resource_id == resource_id)
    )


def _get_owned_resource(
    sess: Session, owned: set[int], resource_id: str
) -> model.Resource:
    resource = sess.scalars(
        select(model.Resource)
        .where(model.Resource.resource_id == resource_id)
        .options(selectinload(model.Resource.app))
    ).one_or_none()
    if resource is None or resource.app_key not in owned:
        raise resource_not_found_error()
    return resource


def _filter_conditions(
    sess: Session,
    owned: set[int],
    filters: ListFilter,
    app_col: InstrumentedAttribute[int],
    resource_col: InstrumentedAttribute[int],
) -> list[ColumnElement[bool]]:
    if (
        filters.app_id is None
        and filters.resource_id is None
        and filters.resource_app_id is None
    ):
        raise filter_required_error()

    conditions: list[ColumnElement[bool]] = []
    sides: list[int | None] = []

    if filters.app_id is not None:
        app_key = _app_key(sess, filters.app_id)
        sides.append(app_key)
        conditions.append(app_col == app_key)

    if filters.resource_id is not None:
        sides.append(_resource_app_key(sess, filters.resource_id))
        conditions.append(
            resource_col
            == select(model.Resource.join_key)
            .where(model.Resource.resource_id == filters.resource_id)
            .scalar_subquery()
        )

    if filters.resource_app_id is not None:
        resource_app_key = _app_key(sess, filters.resource_app_id)
        sides.append(resource_app_key)
        conditions.append(
            resource_col.in_(
                select(model.Resource.join_key).where(
                    model.Resource.app_key == resource_app_key
                )
            )
        )

    if not any(key in owned for key in sides if key is not None):
        raise app_not_found_error()

    return conditions


def _rule_exists(
    sess: Session, app_key: int, resource_key: int, access_type: str
) -> bool:
    return bool(
        sess.scalar(
            select(
                exists().where(
                    model.AppAccessRule.app_key == app_key,
                    model.AppAccessRule.resource_key == resource_key,
                    model.AppAccessRule.access_type == access_type,
                )
            )
        )
    )


def _new_rule(
    app: model.App, resource: model.Resource, access_type: str, timestamp: int
) -> model.AppAccessRule:
    return model.AppAccessRule(
        rule_id=generate_id_token(),
        app=app,
        resource=resource,
        access_type=access_type,
        created_at=timestamp,
        updated_at=timestamp,
    )


def _select_requests() -> Select[model.AppAccessRequest]:
    return select(model.AppAccessRequest).options(
        selectinload(model.AppAccessRequest.app),
        selectinload(model.AppAccessRequest.resource).selectinload(model.Resource.app),
        selectinload(model.AppAccessRequest.requested_by),
        selectinload(model.AppAccessRequest.decided_by),
    )


def _select_grants() -> Select[model.AppAccessRule]:
    return select(model.AppAccessRule).options(
        selectinload(model.AppAccessRule.app),
        selectinload(model.AppAccessRule.resource).selectinload(model.Resource.app),
    )


def _get_request(sess: Session, request_id: str) -> model.AppAccessRequest:
    request = sess.scalars(
        _select_requests().where(model.AppAccessRequest.request_id == request_id)
    ).one_or_none()
    if request is None:
        raise access_request_not_found_error()
    return request


def _get_grant(sess: Session, rule_id: str) -> model.AppAccessRule:
    rule = sess.scalars(
        _select_grants().where(model.AppAccessRule.rule_id == rule_id)
    ).one_or_none()
    if rule is None:
        raise access_grant_not_found_error()
    return rule


def _decide(
    request: model.AppAccessRequest,
    status: AccessRequestStatus,
    user: model.User | None,
    timestamp: int,
) -> None:
    if request.status != AccessRequestStatus.PENDING:
        raise access_request_not_pending_error()
    request.status = status.value
    request.decided_by = user
    request.decided_at = timestamp
    request.updated_at = timestamp


@async_read
def list_resource_policies(
    sess: Session, filters: ResourcePolicyFilter
) -> list[ResourcePolicyView]:
    if filters.resource_id is None and filters.resource_app_id is None:
        raise resource_filter_required_error()

    query = (
        select(model.ResourceAccessPolicy, model.Resource.resource_id)
        .join(model.ResourceAccessPolicy.resource)
        .order_by(model.Resource.join_key, model.ResourceAccessPolicy.access_type)
    )
    if filters.resource_id is not None:
        query = query.where(model.Resource.resource_id == filters.resource_id)
    if filters.resource_app_id is not None:
        query = query.join(model.Resource.app).where(
            model.App.app_id == filters.resource_app_id
        )
    return [
        resource_policy_view(policy, resource_id)
        for policy, resource_id in sess.execute(query).tuples()
    ]


def _get_owned_policy(
    sess: Session, user_id: str, policy_id: str
) -> tuple[model.ResourceAccessPolicy, model.Resource]:
    row = sess.execute(
        select(model.ResourceAccessPolicy, model.Resource)
        .join(model.ResourceAccessPolicy.resource)
        .where(model.ResourceAccessPolicy.policy_id == policy_id)
    ).one_or_none()
    if row is None or row[1].app_key not in _owned_app_keys(sess, user_id):
        raise resource_policy_not_found_error()
    return row.tuple()


@async_write
def create_resource_policy(
    sess: Session, user_id: str, body: ResourcePolicyCreate
) -> ResourcePolicyView:
    resource = _get_owned_resource(
        sess, _owned_app_keys(sess, user_id), body.resource_id
    )
    if sess.scalar(
        select(
            exists().where(
                model.ResourceAccessPolicy.resource_key == resource.join_key,
                model.ResourceAccessPolicy.access_type == body.access_type,
            )
        )
    ):
        raise resource_policy_conflict_error()

    timestamp = to_timestamp(now())
    policy = model.ResourceAccessPolicy(
        policy_id=generate_id_token(),
        resource=resource,
        access_type=body.access_type.value,
        approval=body.approval.value,
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(policy)
    return resource_policy_view(policy, resource.resource_id)


@async_write
def update_resource_policy(
    sess: Session, user_id: str, policy_id: str, body: ResourcePolicyUpdate
) -> ResourcePolicyView:
    policy, resource = _get_owned_policy(sess, user_id, policy_id)
    policy.approval = body.approval.value
    policy.updated_at = to_timestamp(now())
    return resource_policy_view(policy, resource.resource_id)


@async_write
def delete_resource_policy(sess: Session, user_id: str, policy_id: str) -> None:
    policy, _ = _get_owned_policy(sess, user_id, policy_id)
    sess.execute(
        delete(model.ResourceAccessPolicy).where(
            model.ResourceAccessPolicy.join_key == policy.join_key
        )
    )


@async_write
def create_access_request(
    sess: Session, user_id: str, body: AccessRequestCreate
) -> AccessRequestView:
    app = get_owned_app(sess, user_id, body.app_id)
    user = _get_user(sess, user_id)

    resource = sess.scalars(
        select(model.Resource)
        .where(model.Resource.resource_id == body.resource_id)
        .options(selectinload(model.Resource.app))
    ).one_or_none()
    if resource is None:
        raise resource_not_found_error()

    policy = sess.scalars(
        select(model.ResourceAccessPolicy).where(
            model.ResourceAccessPolicy.resource_key == resource.join_key,
            model.ResourceAccessPolicy.access_type == body.access_type,
        )
    ).one_or_none()
    if policy is None:
        raise access_type_not_offered_error()

    if _rule_exists(sess, app.join_key, resource.join_key, body.access_type):
        raise access_already_granted_error()

    if sess.scalar(
        select(
            exists().where(
                model.AppAccessRequest.app_key == app.join_key,
                model.AppAccessRequest.resource_key == resource.join_key,
                model.AppAccessRequest.access_type == body.access_type,
                model.AppAccessRequest.status == AccessRequestStatus.PENDING,
            )
        )
    ):
        raise access_request_pending_error()

    timestamp = to_timestamp(now())
    request = model.AppAccessRequest(
        request_id=generate_id_token(),
        app=app,
        resource=resource,
        access_type=body.access_type.value,
        status=AccessRequestStatus.PENDING.value,
        requested_by=user,
        decided_by=None,
        decided_at=None,
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(request)

    if ApprovalPolicy(policy.approval) is ApprovalPolicy.AUTO_APPROVE:
        _decide(request, AccessRequestStatus.APPROVED, None, timestamp)
        sess.add(_new_rule(app, resource, request.access_type, timestamp))

    return access_request_view(request)


@async_read
def list_access_requests(
    sess: Session, user_id: str, filters: ListFilter
) -> list[AccessRequestView]:
    conditions = _filter_conditions(
        sess,
        _owned_app_keys(sess, user_id),
        filters,
        model.AppAccessRequest.app_key,
        model.AppAccessRequest.resource_key,
    )
    requests = sess.scalars(
        _select_requests()
        .where(*conditions)
        .order_by(
            model.AppAccessRequest.created_at.desc(),
            model.AppAccessRequest.join_key.desc(),
        )
    ).all()
    return [access_request_view(request) for request in requests]


@async_read
def get_access_request(
    sess: Session, user_id: str, request_id: str
) -> AccessRequestView:
    request = _get_request(sess, request_id)
    owned = _owned_app_keys(sess, user_id)
    if request.app_key not in owned and request.resource.app_key not in owned:
        raise access_request_not_found_error()
    return access_request_view(request)


@async_write
def cancel_access_request(
    sess: Session, user_id: str, request_id: str
) -> AccessRequestView:
    request = _get_request(sess, request_id)
    if request.app_key not in _owned_app_keys(sess, user_id):
        raise access_request_not_found_error()
    _decide(
        request,
        AccessRequestStatus.CANCELLED,
        _get_user(sess, user_id),
        to_timestamp(now()),
    )
    return access_request_view(request)


def _get_incoming_request(
    sess: Session, user_id: str, request_id: str
) -> model.AppAccessRequest:
    request = _get_request(sess, request_id)
    if request.resource.app_key not in _owned_app_keys(sess, user_id):
        raise access_request_not_found_error()
    return request


@async_write
def approve_access_request(
    sess: Session, user_id: str, request_id: str
) -> AccessRequestView:
    request = _get_incoming_request(sess, user_id, request_id)
    timestamp = to_timestamp(now())
    _decide(request, AccessRequestStatus.APPROVED, _get_user(sess, user_id), timestamp)
    if not _rule_exists(
        sess, request.app_key, request.resource_key, request.access_type
    ):
        sess.add(
            _new_rule(request.app, request.resource, request.access_type, timestamp)
        )
    return access_request_view(request)


@async_write
def deny_access_request(
    sess: Session, user_id: str, request_id: str
) -> AccessRequestView:
    request = _get_incoming_request(sess, user_id, request_id)
    _decide(
        request,
        AccessRequestStatus.DENIED,
        _get_user(sess, user_id),
        to_timestamp(now()),
    )
    return access_request_view(request)


@async_write
def create_access_grant(
    sess: Session, user_id: str, body: AccessGrantCreate
) -> AccessGrantView:
    resource = _get_owned_resource(
        sess, _owned_app_keys(sess, user_id), body.resource_id
    )
    app = sess.scalars(
        select(model.App).where(model.App.app_id == body.app_id)
    ).one_or_none()
    if app is None:
        raise app_not_found_error()

    if _rule_exists(sess, app.join_key, resource.join_key, body.access_type):
        raise access_already_granted_error()

    timestamp = to_timestamp(now())
    rule = _new_rule(app, resource, body.access_type.value, timestamp)
    sess.add(rule)

    pending = sess.scalars(
        select(model.AppAccessRequest).where(
            model.AppAccessRequest.app_key == app.join_key,
            model.AppAccessRequest.resource_key == resource.join_key,
            model.AppAccessRequest.access_type == body.access_type,
            model.AppAccessRequest.status == AccessRequestStatus.PENDING,
        )
    ).one_or_none()
    if pending is not None:
        _decide(
            pending, AccessRequestStatus.APPROVED, _get_user(sess, user_id), timestamp
        )

    return access_grant_view(rule)


@async_read
def list_access_grants(
    sess: Session, user_id: str, filters: ListFilter
) -> list[AccessGrantView]:
    conditions = _filter_conditions(
        sess,
        _owned_app_keys(sess, user_id),
        filters,
        model.AppAccessRule.app_key,
        model.AppAccessRule.resource_key,
    )
    rules = sess.scalars(
        _select_grants()
        .where(*conditions)
        .order_by(
            model.AppAccessRule.created_at.desc(), model.AppAccessRule.join_key.desc()
        )
    ).all()
    return [access_grant_view(rule) for rule in rules]


def _get_visible_grant(
    sess: Session, user_id: str, rule_id: str
) -> model.AppAccessRule:
    rule = _get_grant(sess, rule_id)
    owned = _owned_app_keys(sess, user_id)
    if rule.app_key not in owned and rule.resource.app_key not in owned:
        raise access_grant_not_found_error()
    return rule


@async_read
def get_access_grant(sess: Session, user_id: str, rule_id: str) -> AccessGrantView:
    return access_grant_view(_get_visible_grant(sess, user_id, rule_id))


@async_write
def delete_access_grant(sess: Session, user_id: str, rule_id: str) -> None:
    rule = _get_visible_grant(sess, user_id, rule_id)
    sess.execute(
        delete(model.AppAccessRule).where(model.AppAccessRule.join_key == rule.join_key)
    )
