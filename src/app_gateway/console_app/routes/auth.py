from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from app_gateway.console_app.auth import clear_session_token, set_session_token
from app_gateway.console_app.oauth_client import get_oauth_client

router = APIRouter(prefix="/api/auth")


_NO_STORE_HEADERS = {"cache-control": "no-store"}


@router.get("/login")
async def console_auth_login(api_request: Request) -> Response:
    client = get_oauth_client()
    redirect_uri = api_request.url_for("console_auth_callback")
    # Drop any stale token so the session cookie (token + authlib state)
    # stays under the browser's 4KB cookie limit.
    clear_session_token(api_request)
    return await client.authorize_redirect(api_request, redirect_uri)


@router.get("/callback")
async def console_auth_callback(api_request: Request) -> Response:
    client = get_oauth_client()
    try:
        token = await client.authorize_access_token(api_request)
    except OAuthError:
        return RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)

    response = RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)
    # Only keep what's needed; the id_token/userinfo would bloat the session
    # cookie past the browser's 4KB limit.
    set_session_token(api_request, token)
    return response


@router.post("/logout")
async def console_auth_logout(api_request: Request) -> Response:
    response = RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)
    clear_session_token(api_request)
    return response
