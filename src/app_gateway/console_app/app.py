from fastapi import FastAPI

from app_gateway.common.sessions import SessionMiddleware
from app_gateway.console_app.routes import (
    apps,
    auth,
    catalog,
    identity_providers,
    policy,
    session,
)
from app_gateway.settings import get_settings

app = FastAPI()

app.include_router(auth.router)
app.include_router(apps.router)
app.include_router(policy.router)
app.include_router(catalog.router)
app.include_router(identity_providers.router)
app.include_router(session.router)

settings = get_settings()

app.add_middleware(
    SessionMiddleware,
    cookie_signing_key_seed=settings.cookie_signing_key_seed.get_secret_value(),
    key_rotation_schedule=settings.key_rotation_schedule,
)
