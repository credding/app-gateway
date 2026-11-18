from functools import lru_cache

from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App

from app_gateway.settings import get_settings

_METADATA_PATH = "/.well-known/oauth-authorization-server"


@lru_cache
def get_oauth_client() -> StarletteOAuth2App:
    settings = get_settings()
    oauth = OAuth()
    return oauth.register(
        name="app_gateway",
        server_metadata_url=settings.auth_server_issuer.rstrip("/") + _METADATA_PATH,
        client_id=settings.console_app_client_id,
        client_secret=settings.console_app_client_secret.get_secret_value(),
        client_kwargs={
            "token_endpoint_auth_method": "client_secret_post",
            "code_challenge_method": "S256",
            "scope": "openid profile",
        },
    )
