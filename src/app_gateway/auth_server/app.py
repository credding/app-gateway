from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader

from app_gateway.auth_server.routes import authorize, metadata, token

templates = Jinja2Templates(
    env=Environment(loader=PackageLoader("app_gateway.auth_server"), autoescape=True)
)

app = FastAPI(openapi_url=None)

app.include_router(metadata.router)
app.include_router(authorize.router)
app.include_router(token.router)

app.mount(
    "/static",
    StaticFiles(packages=[("app_gateway.auth_server", "static")]),
    name="static",
)


@app.get("/")
async def oauth_issuer(request: Request) -> Response:
    return templates.TemplateResponse(request, name="index.html")
