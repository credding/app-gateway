from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app_gateway.auth_server.routes import authorize, metadata, token
from app_gateway.common.http import get_http_client


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    yield

    if get_http_client.cache_info().currsize:
        await get_http_client().aclose()


app = FastAPI(lifespan=lifespan, openapi_url=None)
app.include_router(metadata.router)
app.include_router(authorize.router)
app.include_router(token.router)
