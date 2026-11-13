import base64
import os
from datetime import timedelta
from functools import lru_cache, partial
from pathlib import Path
from typing import Annotated

from pydantic import BeforeValidator, Secret, SecretStr
from pydantic_settings import (
    BaseSettings,
    JsonConfigSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

DATA_DIR = Path(os.getenv("DATA_DIR", default="data"))
SETTINGS_DIR = Path(os.getenv("SETTINGS_DIR", default=DATA_DIR))
SETTINGS_FILE = Path(os.getenv("SETTINGS_FILE", default=SETTINGS_DIR / "settings.json"))
SECRETS_DIR = Path(os.getenv("SECRETS_DIR", default=SETTINGS_DIR / "secrets"))


type Base64Secret = Annotated[
    Secret[bytes],
    BeforeValidator(partial(base64.b64decode, validate=True)),
]


class Settings(BaseSettings):
    auth_server_host: str
    auth_server_issuer: str
    key_rotation_schedule: timedelta = timedelta(days=30)
    token_signing_key_seed: Base64Secret
    cookie_signing_key_seed: Base64Secret
    secret_encryption_key: Base64Secret
    idp_authorization_state_lifetime: timedelta = timedelta(minutes=10)
    authorization_code_lifetime: timedelta = timedelta(minutes=10)
    access_token_lifetime: timedelta = timedelta(minutes=60)
    refresh_token_lifetime: timedelta = timedelta(days=7)

    console_app_host: str
    console_app_client_id: str
    console_app_client_secret: SecretStr

    model_config = SettingsConfigDict(
        json_file=SETTINGS_FILE,
        secrets_dir=SECRETS_DIR,
        extra="ignore",
        hide_input_in_errors=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,  # ruff: ignore[unused-class-method-argument]
        dotenv_settings: PydanticBaseSettingsSource,  # ruff: ignore[unused-class-method-argument]
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            file_secret_settings,
            JsonConfigSettingsSource(settings_cls),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
