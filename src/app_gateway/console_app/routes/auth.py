from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse

from app_gateway.common.clock import now
from app_gateway.common.cookies import Cookie, RequestCookie
from app_gateway.console_app.oauth_client import get_oauth_client
from app_gateway.console_app.schema import ConsoleSession

router = APIRouter()

session_cookie = Cookie(ConsoleSession, "console-session", max_age=timedelta(days=7))

_NO_STORE_HEADERS = {"cache-control": "no-store"}


@router.get("/auth/login")
async def console_auth_login(api_request: Request) -> Response:
    client = get_oauth_client()
    redirect_uri = api_request.url_for("console_auth_callback")
    return await client.authorize_redirect(api_request, redirect_uri)


@router.get("/auth/callback")
async def console_auth_callback(
    api_request: Request,
    console_session: Annotated[RequestCookie[ConsoleSession], Depends(session_cookie)],
) -> Response:
    client = get_oauth_client()
    token = await client.authorize_access_token(api_request)

    response = RedirectResponse("/", status_code=303, headers=_NO_STORE_HEADERS)
    console_session.set_cookie(response, ConsoleSession(token=token), now())
    return response
