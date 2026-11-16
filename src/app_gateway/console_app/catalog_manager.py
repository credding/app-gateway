import json

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from app_gateway.common.clock import to_datetime
from app_gateway.console_app.app_manager import app_not_found_error, resource_view
from app_gateway.console_app.catalog_schema import CatalogApp, OwnerView
from app_gateway.db import async_read
from app_gateway.db import policy_model as model


def _str_claim(claims: dict[str, object], key: str) -> str | None:
    value = claims.get(key)
    return value if isinstance(value, str) and value else None


def _owner_view(user: model.User) -> OwnerView:
    # Only expose display fields; other users' full claims stay private.
    claims = json.loads(user.claims)
    return OwnerView(
        user_id=user.user_id,
        name=_str_claim(claims, "name"),
        pronouns=_str_claim(claims, "pronouns"),
    )


def _catalog_app(app: model.App, user_id: str) -> CatalogApp:
    return CatalogApp(
        app_id=app.app_id,
        slug=app.slug,
        name=app.name,
        owners=[_owner_view(owner.user) for owner in app.owners],
        resources=[resource_view(resource) for resource in app.resources],
        is_owner=any(owner.user.user_id == user_id for owner in app.owners),
        created_at=to_datetime(app.created_at),
        updated_at=to_datetime(app.updated_at),
    )


def _select_catalog_apps() -> Select[model.App]:
    return select(model.App).options(
        selectinload(model.App.owners).selectinload(model.AppOwner.user),
        selectinload(model.App.resources),
    )


@async_read
def list_catalog(sess: Session, user_id: str) -> list[CatalogApp]:
    apps = sess.scalars(
        _select_catalog_apps().order_by(model.App.name, model.App.join_key)
    ).all()
    return [_catalog_app(app, user_id) for app in apps]


@async_read
def get_catalog_app(sess: Session, user_id: str, app_slug: str) -> CatalogApp:
    app = sess.scalars(
        _select_catalog_apps().where(model.App.slug == app_slug)
    ).one_or_none()
    if app is None:
        raise app_not_found_error()
    return _catalog_app(app, user_id)
