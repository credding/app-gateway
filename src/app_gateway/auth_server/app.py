from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader

from app_gateway.auth_server.routes import authorize, metadata, token
from app_gateway.settings import SETTINGS_DIR

templates = Jinja2Templates(
    env=Environment(
        loader=ChoiceLoader(
            [
                FileSystemLoader(SETTINGS_DIR / "branding/templates"),
                PackageLoader("app_gateway.default_branding", "templates"),
            ]
        ),
        autoescape=True,
    )
)

app = FastAPI(openapi_url=None)

app.include_router(metadata.router)
app.include_router(authorize.router)
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
