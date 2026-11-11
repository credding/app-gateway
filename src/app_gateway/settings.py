import base64
import os
from datetime import timedelta
from functools import lru_cache, partial
from typing import Annotated

from annotated_types import Len
from pydantic import BeforeValidator, Secret
from pydantic_settings import (
    BaseSettings,
    JsonConfigSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

DATA_DIR = os.getenv("DATA_DIR", default="data")
SETTINGS_DIR = os.getenv("SETTINGS_DIR", default=DATA_DIR)
SETTINGS_FILE = os.getenv("SETTINGS_FILE", default=f"{SETTINGS_DIR}/settings.json")
SECRETS_DIR = os.getenv("SECRETS_DIR", default=f"{SETTINGS_DIR}/secrets")


type Base64Secret = Annotated[
    Secret[bytes],
    BeforeValidator(partial(base64.b64decode, validate=True)),
]

type Base64SecretSeed = Annotated[Base64Secret, Len(min_length=32)]
type Base64SecretKey = Annotated[Base64Secret, Len(min_length=32, max_length=32)]


class Settings(BaseSettings):
    auth_server_issuer: str
    key_rotation_schedule: timedelta = timedelta(days=30)
    token_signing_key_seed: Base64Secret
    cookie_signing_key_seed: Base64Secret
    secret_encryption_key: Base64Secret
    access_token_lifetime: timedelta = timedelta(minutes=60)
    refresh_token_lifetime: timedelta = timedelta(days=7)

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
        init_settings: PydanticBaseSettingsSource,  # ruff: ignore[unused-class-method-argument]
        env_settings: PydanticBaseSettingsSource,  # ruff: ignore[unused-class-method-argument]
        dotenv_settings: PydanticBaseSettingsSource,  # ruff: ignore[unused-class-method-argument]
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            file_secret_settings,
            JsonConfigSettingsSource(settings_cls),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
