from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app_gateway.common.clock import now
from app_gateway.console_app.routes import apps, auth, identity_providers, session
from app_gateway.console_app.static import SPAStaticFiles
from app_gateway.crypto.key_management import derive_private_bytes, normalize_time
from app_gateway.settings import get_settings

app = FastAPI()

app.include_router(auth.router)
app.include_router(apps.router)
app.include_router(identity_providers.router)
app.include_router(session.router)


def _session_secret_key() -> bytes:
    # Only holds in-flight login state (state + PKCE verifier), so a key fixed
    # at startup is fine; flows straddling a restart across a rotation fail.
    settings = get_settings()
    return derive_private_bytes(
        settings.cookie_signing_key_seed.get_secret_value(),
        normalize_time(now(), settings.key_rotation_schedule),
    )


app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret_key().hex(),
    session_cookie="__Host-console-oauth",
    max_age=600,
    path="/",
    same_site="lax",
    https_only=True,
)

# Mounted last so the API and auth routes above take precedence.
app.mount(
    "/",
    SPAStaticFiles(
        directory=get_settings().console_app_web_dir,
        html=True,
        check_dir=False,
    ),
    name="web",
)
