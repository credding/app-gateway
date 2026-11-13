from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.routing import BaseRoute, Host

from app_gateway.auth_server import app as auth_server
from app_gateway.common.http import get_http_client
from app_gateway.console_app import app as console_app
from app_gateway.settings import get_settings


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    yield

    if get_http_client.cache_info().currsize:
        await get_http_client().aclose()


settings = get_settings()

routes: list[BaseRoute] = [
    Host(settings.auth_server_host, auth_server.app),
    Host(settings.console_app_host, console_app.app),
]


app = FastAPI(routes=routes, lifespan=lifespan)
