from typing import NamedTuple

from sqlalchemy import select
from sqlalchemy.orm import Session, contains_eager, sessionmaker

from app_gateway import policy_model as model
from app_gateway import policy_schema as schema
from app_gateway.common.db import read_session, run_read, write_session
from app_gateway.policy_schema import AccessType


class ClientAppIdentityProviders(NamedTuple):
    client: schema.Client
    identity_providers: list[AppIdentityProvider]


class AppIdentityProvider(NamedTuple):
    app_idp: schema.AppIdentityProvider
    idp: schema.IdentityProvider


class PolicyManager:
    def __init__(
        self,
        read_session: sessionmaker[Session] = read_session,
        write_session: sessionmaker[Session] = write_session,
    ) -> None:
        self.read_session = read_session
        self.write_session = write_session

    async def get_client_app_idps(
        self,
        client_id: str,
    ) -> ClientAppIdentityProviders | None:
        return await run_read(lambda: self._get_client_app_idps(client_id))

    async def get_client_app_access_rule(
        self,
        client_id: str,
        resource_uri: str,
        access_type: AccessType,
    ) -> schema.AppAccessRule | None:
        return await run_read(
            lambda: self._get_client_app_access_rule(
                client_id, resource_uri, access_type
            )
        )

    def _get_client_app_idps(
        self,
        client_id: str,
    ) -> ClientAppIdentityProviders | None:
        with self.read_session() as sess:
            client = sess.scalar(
                select(model.Client)
                .join(model.Client.app)
                .outerjoin(
                    model.AppIdentityProvider.__table__.join(
                        model.IdentityProvider.__table__
                    )
                )
                .where(model.Client.client_id == client_id)
                .options(
                    contains_eager(model.Client.app)
                    .contains_eager(model.App.identity_providers)
                    .contains_eager(model.AppIdentityProvider.app),
                    contains_eager(model.Client.app)
                    .contains_eager(model.App.identity_providers)
                    .contains_eager(model.AppIdentityProvider.identity_provider),
                )
            )
            if client is None:
                return None

            return ClientAppIdentityProviders(
                client=client.to_schema(),
                identity_providers=[
                    AppIdentityProvider(
                        app_idp.to_schema(),
                        app_idp.identity_provider.to_schema(),
                    )
                    for app_idp in client.app.identity_providers
                ],
            )

    def _get_client_app_access_rule(
        self,
        client_id: str,
        resource_uri: str,
        access_type: AccessType,
    ) -> schema.AppAccessRule | None:
        with self.read_session() as sess:
            access_rule = sess.scalar(
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

            if access_rule is None:
                return None

            return access_rule.to_schema()
