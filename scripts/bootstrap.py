#!/usr/bin/env python3

import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import assert_never

from alembic import command
from alembic.config import Config
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app_gateway.common.clock import now, to_timestamp
from app_gateway.common.tokens import generate_secret_key, hash_token
from app_gateway.db import policy_model as model
from app_gateway.db import write_session
from app_gateway.oauth.tokens import (
    generate_client_secret,
    generate_confidential_client_id,
)
from app_gateway.policy import (
    ClientType,
    encrypt_app_idp_client_secret,
    generate_app_id,
    generate_idp_id,
)
from app_gateway.settings import DATA_DIR, SECRETS_DIR, SETTINGS_FILE, Settings


class BootstrapConfig(BaseModel):
    identity_provider: BootstrapIdentityProvider
    auth_server: BootstrapAuthServer
    console_app: BootstrapConsoleApp


class BootstrapIdentityProvider(BaseModel):
    name: str
    issuer: str
    slug: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    userinfo_claims_map: dict[str, str]


class BootstrapAuthServer(BaseModel):
    issuer: str


class BootstrapConsoleApp(BaseModel):
    origin: str
    identity_provider: BootstrapIdpCredentials


class BootstrapIdpCredentials(BaseModel):
    client_id: str
    client_secret: str


def main() -> None:
    match sys.argv:
        case [_]:
            config_path = DATA_DIR / "bootstrap.json"
        case [_, bootstrap_file]:
            config_path = Path(bootstrap_file)
        case list():
            sys.exit(1)
        case unreachable:
            assert_never(unreachable)

    config = BootstrapConfig.model_validate_json(config_path.read_bytes())
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

    run_db_migrations()
    init_secrets()
    settings = init_settings(config)
    init_policy_db(config, settings, now())


def run_db_migrations() -> None:
    command.upgrade(Config(toml_file="pyproject.toml"), "head")


def init_secrets() -> None:
    SECRETS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    _init_secret("token_signing_key_seed", generate_secret_key)
    _init_secret("cookie_signing_key_seed", generate_secret_key)
    _init_secret("secret_encryption_key", generate_secret_key)

    _init_secret("console_app_client_secret", generate_client_secret)


def _init_secret(name: str, generate: Callable[[], str]) -> None:
    path = SECRETS_DIR / name

    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(generate())
    except FileExistsError:
        pass


def init_settings(config: BootstrapConfig) -> Settings:
    path = SETTINGS_FILE

    settings = json.loads(path.read_text()) if path.exists() else {}
    settings.setdefault("auth_server_issuer", config.auth_server.issuer)
    settings.setdefault("console_app_client_id", generate_confidential_client_id())
    path.write_text(json.dumps(settings, indent=2))

    return Settings()


def init_policy_db(
    config: BootstrapConfig,
    settings: Settings,
    time: datetime,
) -> None:
    timestamp = to_timestamp(time)

    with write_session.begin() as sess:
        idp = _init_identity_provider(sess, config.identity_provider, timestamp)
        app = _init_app(sess, timestamp)
        _init_app_idp(
            sess,
            app,
            idp,
            config.console_app.identity_provider,
            settings.secret_encryption_key.get_secret_value(),
            timestamp,
        )
        _init_console_client(
            sess,
            app,
            settings.console_app_client_id,
            settings.console_app_client_secret.get_secret_value(),
            config.console_app.origin,
            timestamp,
        )


def _init_identity_provider(
    sess: Session,
    config: BootstrapIdentityProvider,
    timestamp: int,
) -> model.IdentityProvider:
    idp = sess.scalars(
        select(model.IdentityProvider).where(
            model.IdentityProvider.issuer == config.issuer
        )
    ).one_or_none()

    if idp is not None:
        return idp

    idp = model.IdentityProvider(
        idp_id=generate_idp_id(),
        issuer=config.issuer,
        slug=config.slug,
        name=config.name,
        authorization_endpoint=config.authorization_endpoint,
        token_endpoint=config.token_endpoint,
        userinfo_endpoint=config.userinfo_endpoint,
        userinfo_claims_map=json.dumps(config.userinfo_claims_map),
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(idp)
    return idp


def _init_app(
    sess: Session,
    timestamp: int,
) -> model.App:
    app = sess.scalars(
        select(model.App).where(model.App.slug == "app-gateway")
    ).one_or_none()

    if app is not None:
        return app

    app = model.App(
        app_id=generate_app_id(),
        slug="app-gateway",
        name="App Gateway",
        created_at=timestamp,
        updated_at=timestamp,
    )
    sess.add(app)
    return app


def _init_app_idp(
    sess: Session,
    app: model.App,
    idp: model.IdentityProvider,
    creds: BootstrapIdpCredentials,
    encryption_key: bytes,
    timestamp: int,
) -> None:
    app_idp = sess.scalars(
        select(model.AppIdentityProvider).where(
            model.AppIdentityProvider.app_key == app.join_key,
            model.AppIdentityProvider.idp_key == idp.join_key,
        )
    ).one_or_none()

    if app_idp is not None:
        return

    sess.add(
        model.AppIdentityProvider(
            app=app,
            idp=idp,
            client_id=creds.client_id,
            client_secret_enc=encrypt_app_idp_client_secret(
                encryption_key, app.app_id, idp.idp_id, creds.client_secret
            ),
            created_at=timestamp,
            updated_at=timestamp,
        )
    )


def _init_console_client(
    sess: Session,
    app: model.App,
    client_id: str,
    client_secret: str,
    origin: str,
    timestamp: int,
) -> None:
    client = sess.scalars(
        select(model.Client).where(model.Client.client_id == client_id)
    ).one_or_none()

    if client is not None:
        return

    sess.add(
        model.Client(
            app=app,
            client_type=ClientType.CONFIDENTIAL.value,
            name="Console App",
            client_id=client_id,
            client_secret_hash=hash_token(client_secret),
            redirect_uris=json.dumps([origin.rstrip("/") + "/auth/callback"]),
            created_at=timestamp,
            updated_at=timestamp,
        )
    )


if __name__ == "__main__":
    main()
