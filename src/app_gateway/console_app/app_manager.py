import json

from fastapi import HTTPException
from sqlalchemy import delete, exists, select
from sqlalchemy.orm import Session, selectinload

from app_gateway.common.clock import now, to_datetime, to_timestamp
from app_gateway.common.tokens import hash_token
from app_gateway.console_app.app_schema import (
    AppCreate,
    AppIdpUpdate,
    AppIdpView,
    AppUpdate,
    AppView,
    ClientCreate,
    ClientSecretView,
    ClientUpdate,
    ClientView,
    ListAppsItem,
    ResourceCreate,
    ResourceUpdate,
    ResourceView,
    UserView,
)
from app_gateway.crypto.encrypt import generate_nonce
from app_gateway.db import async_read, async_write
from app_gateway.db import policy_model as model
from app_gateway.oauth.tokens import (
    generate_client_secret,
    generate_confidential_client_id,
    generate_public_client_id,
)
from app_gateway.policy import (
    ClientType,
    encrypt_app_idp_client_secret,
    generate_app_id,
    generate_resource_id,
)


def app_manager_error(detail: str, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code, detail, {"cache-control": "no-store"})


def app_not_found_error() -> HTTPException:
    return app_manager_error("app not found", 404)


def user_not_found_error() -> HTTPException:
    return app_manager_error("user not found", 404)


def idp_not_found_error() -> HTTPException:
    return app_manager_error("identity provider not found", 404)


def client_not_found_error() -> HTTPException:
    return app_manager_error("client not found", 404)


def resource_not_found_error() -> HTTPException:
    return app_manager_error("resource not found", 404)


def slug_conflict_error() -> HTTPException:
    return app_manager_error("slug already in use", 409)


def resource_uri_conflict_error() -> HTTPException:
    return app_manager_error("resource uri already in use", 409)


def console_app_delete_error() -> HTTPException:
    return app_manager_error("cannot delete the console app")


def public_client_secret_error() -> HTTPException:
    return app_manager_error("only confidential clients have a secret")


def _app_view(app: model.App) -> AppView:
    return AppView(app_id=app.app_id, slug=app.slug, name=app.name)


def _app_idp_view(app_idp: model.AppIdentityProvider) -> AppIdpView:
    return AppIdpView(
        idp_id=app_idp.idp.idp_id,
        name=app_idp.idp.name,
        client_id=app_idp.client_id,
    )


def _client_view(client: model.Client) -> ClientView:
    return ClientView(
        client_type=ClientType(client.client_type),
        name=client.name,
        client_id=client.client_id,
        redirect_uris=json.loads(client.redirect_uris),
        created_at=to_datetime(client.created_at),
        updated_at=to_datetime(client.updated_at),
    )


def _client_secret_view(
    client: model.Client, client_secret: str | None
) -> ClientSecretView:
    return ClientSecretView(
        client_type=ClientType(client.client_type),
        name=client.name,
        client_id=client.client_id,
        client_secret=client_secret,
        redirect_uris=json.loads(client.redirect_uris),
        created_at=to_datetime(client.created_at),
        updated_at=to_datetime(client.updated_at),
    )


def _resource_view(resource: model.Resource) -> ResourceView:
    return ResourceView(
        resource_id=resource.resource_id,
        name=resource.name,
        uri=resource.uri,
        created_at=to_datetime(resource.created_at),
        updated_at=to_datetime(resource.updated_at),
    )


def _get_owned_app(sess: Session, user_id: str, app_id: str) -> model.App:
    app = sess.scalars(
        select(model.App)
        .join(model.App.owners)
        .join(model.AppOwner.user)
        .where(model.App.app_id == app_id, model.User.user_id == user_id)
    ).one_or_none()
    if app is None:
        raise app_not_found_error()
    return app


def _get_owned_client(
    sess: Session, user_id: str, app_id: str, client_id: str
) -> model.Client:
    client = sess.scalars(
        select(model.Client)
        .join(model.Client.app)
        .join(model.App.owners)
        .join(model.AppOwner.user)
        .where(
            model.App.app_id == app_id,
            model.Client.client_id == client_id,
            model.User.user_id == user_id,
        )
    ).one_or_none()
    if client is None:
        raise client_not_found_error()
    return client


def _get_owned_resource(
    sess: Session, user_id: str, app_id: str, resource_id: str
) -> model.Resource:
    resource = sess.scalars(
        select(model.Resource)
        .join(model.Resource.app)
        .join(model.App.owners)
        .join(model.AppOwner.user)
        .where(
            model.App.app_id == app_id,
            model.Resource.resource_id == resource_id,
            model.User.user_id == user_id,
        )
    ).one_or_none()
    if resource is None:
        raise resource_not_found_error()
    return resource


def _check_slug_available(sess: Session, slug: str) -> None:
    if sess.scalar(select(exists().where(model.App.slug == slug))):
        raise slug_conflict_error()


def _check_uri_available(sess: Session, uri: str) -> None:
    if sess.scalar(select(exists().where(model.Resource.uri == uri))):
        raise resource_uri_conflict_error()


@async_read
def list_apps(sess: Session, user_id: str) -> list[ListAppsItem]:
    apps = sess.scalars(
        select(model.App)
        .join(model.App.owners)
        .join(model.AppOwner.user)
        .where(model.User.user_id == user_id)
        .order_by(model.App.created_at, model.App.join_key)
        .options(
            selectinload(model.App.owners).selectinload(model.AppOwner.user),
            selectinload(model.App.idps).selectinload(model.AppIdentityProvider.idp),
            selectinload(model.App.clients),
            selectinload(model.App.resources),
        )
    ).all()

    return [
        ListAppsItem(
            app_id=app.app_id,
            slug=app.slug,
            name=app.name,
            owners=[
                UserView(
                    user_id=owner.user.user_id,
                    claims=json.loads(owner.user.claims),
                )
                for owner in app.owners
            ],
            idps=[_app_idp_view(app_idp) for app_idp in app.idps],
            clients=[_client_view(client) for client in app.clients],
            resources=[_resource_view(resource) for resource in app.resources],
            created_at=to_datetime(app.created_at),
            updated_at=to_datetime(app.updated_at),
        )
        for app in apps
    ]


@async_write
def create_app(sess: Session, user_id: str, body: AppCreate) -> AppView:
    user = sess.scalars(
        select(model.User).where(model.User.user_id == user_id)
    ).one_or_none()
    if user is None:
        raise user_not_found_error()

    _check_slug_available(sess, body.slug)

    timestamp = to_timestamp(now())
    app = model.App(
        app_id=generate_app_id(),
        slug=body.slug,
        name=body.name,
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(app)
    sess.add(
        model.AppOwner(
            app=app,
            user=user,
            created_at=timestamp,
            updated_at=timestamp,
        )
    )
    return _app_view(app)


@async_write
def update_app(sess: Session, user_id: str, app_id: str, body: AppUpdate) -> AppView:
    app = _get_owned_app(sess, user_id, app_id)

    if body.slug is not None and body.slug != app.slug:
        _check_slug_available(sess, body.slug)
        app.slug = body.slug
    if body.name is not None:
        app.name = body.name
    app.updated_at = to_timestamp(now())

    return _app_view(app)


@async_write
def delete_app(sess: Session, user_id: str, app_id: str) -> None:
    app = _get_owned_app(sess, user_id, app_id)
    sess.execute(delete(model.App).where(model.App.join_key == app.join_key))


@async_write
def put_app_idp(
    sess: Session,
    user_id: str,
    app_id: str,
    idp_id: str,
    body: AppIdpUpdate,
    encryption_key: bytes,
) -> AppIdpView:
    app = _get_owned_app(sess, user_id, app_id)

    idp = sess.scalars(
        select(model.IdentityProvider).where(model.IdentityProvider.idp_id == idp_id)
    ).one_or_none()
    if idp is None:
        raise idp_not_found_error()

    client_secret_enc = encrypt_app_idp_client_secret(
        encryption_key,
        generate_nonce(),
        app.app_id,
        idp.idp_id,
        body.client_secret,
    )
    timestamp = to_timestamp(now())

    app_idp = sess.scalars(
        select(model.AppIdentityProvider).where(
            model.AppIdentityProvider.app_key == app.join_key,
            model.AppIdentityProvider.idp_key == idp.join_key,
        )
    ).one_or_none()
    if app_idp is None:
        app_idp = model.AppIdentityProvider(
            app=app,
            idp=idp,
            client_id=body.client_id,
            client_secret_enc=client_secret_enc,
            created_at=timestamp,
            updated_at=timestamp,
        )
        sess.add(app_idp)
    else:
        app_idp.client_id = body.client_id
        app_idp.client_secret_enc = client_secret_enc
        app_idp.updated_at = timestamp

    return AppIdpView(idp_id=idp.idp_id, name=idp.name, client_id=app_idp.client_id)


@async_write
def delete_app_idp(sess: Session, user_id: str, app_id: str, idp_id: str) -> None:
    app = _get_owned_app(sess, user_id, app_id)

    app_idp_key = sess.scalar(
        select(model.AppIdentityProvider.join_key)
        .join(model.AppIdentityProvider.idp)
        .where(
            model.AppIdentityProvider.app_key == app.join_key,
            model.IdentityProvider.idp_id == idp_id,
        )
    )
    if app_idp_key is None:
        raise idp_not_found_error()

    sess.execute(
        delete(model.AppIdentityProvider).where(
            model.AppIdentityProvider.join_key == app_idp_key
        )
    )


@async_write
def create_client(
    sess: Session, user_id: str, app_id: str, body: ClientCreate
) -> ClientSecretView:
    app = _get_owned_app(sess, user_id, app_id)

    match body.client_type:
        case ClientType.CONFIDENTIAL:
            client_id = generate_confidential_client_id()
            client_secret = generate_client_secret()
            client_secret_hash = hash_token(client_secret)
        case ClientType.PUBLIC:
            client_id = generate_public_client_id()
            client_secret = None
            client_secret_hash = None

    timestamp = to_timestamp(now())
    client = model.Client(
        app=app,
        client_type=body.client_type.value,
        name=body.name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        redirect_uris=json.dumps(body.redirect_uris),
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(client)

    return _client_secret_view(client, client_secret)


@async_write
def update_client(
    sess: Session, user_id: str, app_id: str, client_id: str, body: ClientUpdate
) -> ClientView:
    client = _get_owned_client(sess, user_id, app_id, client_id)

    if body.name is not None:
        client.name = body.name
    if body.redirect_uris is not None:
        client.redirect_uris = json.dumps(body.redirect_uris)
    client.updated_at = to_timestamp(now())

    return _client_view(client)


@async_write
def rotate_client_secret(
    sess: Session, user_id: str, app_id: str, client_id: str
) -> ClientSecretView:
    client = _get_owned_client(sess, user_id, app_id, client_id)

    if client.client_type != ClientType.CONFIDENTIAL:
        raise public_client_secret_error()

    client_secret = generate_client_secret()
    client.client_secret_hash = hash_token(client_secret)
    client.updated_at = to_timestamp(now())

    return _client_secret_view(client, client_secret)


@async_write
def delete_client(
    sess: Session,
    user_id: str,
    app_id: str,
    client_id: str,
) -> None:
    client = _get_owned_client(sess, user_id, app_id, client_id)
    sess.execute(delete(model.Client).where(model.Client.join_key == client.join_key))


@async_write
def create_resource(
    sess: Session, user_id: str, app_id: str, body: ResourceCreate
) -> ResourceView:
    app = _get_owned_app(sess, user_id, app_id)

    _check_uri_available(sess, body.uri)

    timestamp = to_timestamp(now())
    resource = model.Resource(
        app=app,
        resource_id=generate_resource_id(),
        name=body.name,
        uri=body.uri,
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(resource)

    return _resource_view(resource)


@async_write
def update_resource(
    sess: Session, user_id: str, app_id: str, resource_id: str, body: ResourceUpdate
) -> ResourceView:
    resource = _get_owned_resource(sess, user_id, app_id, resource_id)

    if body.uri is not None and body.uri != resource.uri:
        _check_uri_available(sess, body.uri)
        resource.uri = body.uri
    if body.name is not None:
        resource.name = body.name
    resource.updated_at = to_timestamp(now())

    return _resource_view(resource)


@async_write
def delete_resource(sess: Session, user_id: str, app_id: str, resource_id: str) -> None:
    resource = _get_owned_resource(sess, user_id, app_id, resource_id)

    sess.execute(
        delete(model.Resource).where(model.Resource.join_key == resource.join_key)
    )
