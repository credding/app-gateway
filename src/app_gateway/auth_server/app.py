from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from app_gateway.auth_server.routes import authorize, device, metadata, token
from app_gateway.auth_server.templates import templates
from app_gateway.settings import SETTINGS_DIR

app = FastAPI(openapi_url=None)

app.include_router(metadata.router)
app.include_router(authorize.router)
app.include_router(device.router)
app.include_router(token.router)


@app.get("/")
async def oauth_issuer(request: Request) -> Response:
    return templates.TemplateResponse(request, name="auth-server-index.html")


branding_static_files = SETTINGS_DIR / "branding/static"
app.mount(
    "/",
    StaticFiles(
        directory=branding_static_files if branding_static_files.exists() else None,
        packages=[("app_gateway.default_branding", "static")],
    ),
    name="static",
)
