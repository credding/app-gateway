from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from app_gateway.console_app.oauth_client import get_oauth_client

router = APIRouter(prefix="/api/auth")


_NO_STORE_HEADERS = {"cache-control": "no-store"}


@router.get("/login")
async def console_auth_login(api_request: Request) -> Response:
    client = get_oauth_client()
    redirect_uri = api_request.url_for("console_auth_callback")
    return await client.authorize_redirect(api_request, redirect_uri)


@router.get("/callback")
async def console_auth_callback(api_request: Request) -> Response:
    client = get_oauth_client()
    token = await client.authorize_access_token(api_request)

    response = RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)
    api_request.session["token"] = token
    return response


@router.post("/logout")
async def console_auth_logout(api_request: Request) -> Response:
    response = RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)
    api_request.session.pop("token", None)
    return response
