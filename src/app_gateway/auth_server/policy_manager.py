import json
from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session, contains_eager

from app_gateway.common.clock import to_timestamp
from app_gateway.db import async_read, async_write
from app_gateway.db import policy_model as model
from app_gateway.policy import schema


class ClientAppIdentityProviders(NamedTuple):
    client: schema.Client
    app_idps: list[AppIdpIdentityProvider]


class AppIdpIdentityProvider(NamedTuple):
    app_idp: schema.AppIdentityProvider
    idp: schema.IdentityProvider


class UserIdentity(NamedTuple):
    user: schema.User
    identity: schema.UserIdentity
    idp: schema.IdentityProvider


@async_read
def lookup_client(
    sess: Session,
    client_id: str,
) -> schema.Client | None:
    result = sess.scalars(
        select(model.Client)
        .join(model.Client.app)
        .where(model.Client.client_id == client_id)
        .options(contains_eager(model.Client.app))
    )
    client = result.one_or_none()

    if client is None:
        return None

    return client.to_schema()


@async_read
def lookup_client_app_idp(
    sess: Session, client_id: str, idp_issuer: str
) -> AppIdpIdentityProvider | None:
    result = sess.scalars(
        select(model.AppIdentityProvider)
        .join(model.AppIdentityProvider.idp)
        .join(model.AppIdentityProvider.app)
        .join(model.Client, model.Client.app_key == model.App.join_key)
        .where(
            model.Client.client_id == client_id,
            model.IdentityProvider.issuer == idp_issuer,
        )
        .options(
            contains_eager(model.AppIdentityProvider.app),
            contains_eager(model.AppIdentityProvider.idp),
        )
    )
    app_idp = result.one_or_none()

    if app_idp is None:
        return None

    return AppIdpIdentityProvider(
        app_idp.to_schema(),
        app_idp.idp.to_schema(),
    )


@async_read
def lookup_client_app_idps(
    sess: Session,
    client_id: str,
) -> ClientAppIdentityProviders | None:
    result = sess.scalars(
        select(model.Client)
        .join(model.Client.app)
        .outerjoin(
            model.AppIdentityProvider.__table__.join(model.IdentityProvider.__table__)
        )
        .where(model.Client.client_id == client_id)
        .options(
            contains_eager(model.Client.app)
            .contains_eager(model.App.idps)
            .contains_eager(model.AppIdentityProvider.app),
            contains_eager(model.Client.app)
            .contains_eager(model.App.idps)
            .contains_eager(model.AppIdentityProvider.idp),
        )
    )
    client = result.unique().one_or_none()

    if client is None:
        return None

    return ClientAppIdentityProviders(
        client.to_schema(),
        [
            AppIdpIdentityProvider(
                app_idp.to_schema(),
                app_idp.idp.to_schema(),
            )
            for app_idp in client.app.idps
        ],
    )


@async_read
def lookup_app_access_rule(
    sess: Session,
    client_id: str,
    resource_uri: str,
    access_type: schema.AccessType,
) -> schema.AppAccessRule | None:
    result = sess.scalars(
        select(model.AppAccessRule)
        .join(model.AppAccessRule.app)
        .join(model.Client, model.Client.app_key == model.App.join_key)
        .join(model.AppAccessRule.resource)
        .where(
            model.Client.client_id == client_id,
            model.Resource.uri == resource_uri,
            model.AppAccessRule.access_type == access_type,
        )
        .options(
            contains_eager(model.AppAccessRule.app),
            contains_eager(model.AppAccessRule.resource),
        )
    )
    access_rule = result.one_or_none()

    if access_rule is None:
        return None

    return access_rule.to_schema()


@async_read
def lookup_resource(sess: Session, resource_uri: str) -> schema.Resource | None:
    result = sess.scalars(
        select(model.Resource)
        .join(model.Resource.app)
        .where(model.Resource.uri == resource_uri)
        .options(contains_eager(model.Resource.app))
    )
    resource = result.one_or_none()

    if resource is None:
        return None

    return resource.to_schema()


@async_read
def lookup_user(
    sess: Session,
    idp_issuer: str,
    idp_subject: str,
) -> schema.User | None:
    result = sess.scalars(
        select(model.User)
        .join(model.UserIdentity, model.UserIdentity.user_key == model.User.join_key)
        .join(model.UserIdentity.idp)
        .where(
            model.IdentityProvider.issuer == idp_issuer,
            model.UserIdentity.idp_subject == idp_subject,
        )
    )
    user = result.one_or_none()

    if user is None:
        return None

    return user.to_schema()


@async_read
def lookup_user_identity(
    sess: Session,
    idp_issuer: str,
    user_id: str,
) -> UserIdentity | None:
    result = sess.scalars(
        select(model.UserIdentity)
        .join(model.UserIdentity.user)
        .join(model.UserIdentity.idp)
        .where(
            model.IdentityProvider.issuer == idp_issuer,
            model.User.user_id == user_id,
        )
        .options(
            contains_eager(model.UserIdentity.user),
            contains_eager(model.UserIdentity.idp),
        )
    )
    identity = result.one_or_none()

    if identity is None:
        return None

    return UserIdentity(
        user=identity.user.to_schema(),
        identity=identity.to_schema(),
        idp=identity.idp.to_schema(),
    )


@async_write
def register_user(
    sess: Session,
    idp_issuer: str,
    idp_subject: str,
    user_id: str,
    claims: dict[str, Any],
    time: datetime,
) -> schema.User:
    claims_json = json.dumps(claims)
    timestamp = to_timestamp(time)

    idp_key = sess.scalars(
        select(model.IdentityProvider.join_key).where(
            model.IdentityProvider.issuer == idp_issuer
        )
    ).one_or_none()

    user = model.User(
        user_id=user_id,
        claims=claims_json,
        created_at=timestamp,
        updated_at=timestamp,
    )
    user_identity = model.UserIdentity(
        user=user,
        idp_key=idp_key,
        idp_subject=idp_subject,
        created_at=timestamp,
        updated_at=timestamp,
    )

    sess.add(user)
    sess.add(user_identity)

    return user.to_schema()


@async_write
def update_user_claims(
    sess: Session,
    user: schema.User,
    claims: dict[str, Any],
    time: datetime,
) -> schema.User:
    claims_json = json.dumps(claims)
    timestamp = to_timestamp(time)

    model_user = sess.scalars(
        select(model.User).where(model.User.user_id == user.user_id)
    ).one()
    model_user.claims = claims_json
    model_user.updated_at = timestamp

    return model_user.to_schema()
