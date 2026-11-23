from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app_gateway.auth_server.routes import authorize, device, metadata, token, userinfo

app = FastAPI(openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(metadata.router)
app.include_router(authorize.router)
app.include_router(device.router)
app.include_router(token.router)
app.include_router(userinfo.router)
