from datetime import timedelta
from typing import Any, Literal

from itsdangerous.exc import BadSignature
from pydantic import BaseModel
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import Session
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app_gateway.common.clock import now
from app_gateway.common.cookies import Signer

_DEFAULT_MAX_AGE = timedelta(days=7)


# Modified from: https://github.com/Kludex/starlette/blob/main/starlette/middleware/sessions.py
class SessionMiddleware[T: BaseModel]:
    def __init__(
        self,
        app: ASGIApp,
        cookie_signing_key_seed: bytes,
        key_rotation_schedule: timedelta,
        session_cookie: str = "__Host-session",
        max_age: timedelta = _DEFAULT_MAX_AGE,
        same_site: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        self._signer = Signer(
            dict[str, Any],
            session_cookie,
            cookie_signing_key_seed,
            key_rotation_schedule,
            max_age,
        )
        self.app = app
        self.cookie_signing_key_seed = cookie_signing_key_seed
        self.key_rotation_schedule = key_rotation_schedule
        self.session_cookie = session_cookie
        self.max_age = max_age
        self.security_flags = "httponly; samesite=" + same_site
        self.security_flags += "; secure"
        if same_site == "none":
            self.security_flags += "; partitioned"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True
        time = now()

        if self.session_cookie in connection.cookies:
            data = connection.cookies[self.session_cookie].encode("utf-8")
            try:
                scope["session"] = Session(self._signer.unsign(data, time))
                initial_session_was_empty = False
            except BadSignature:
                scope["session"] = Session()
        else:
            scope["session"] = Session()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                session: Session = scope["session"]
                message.setdefault("headers", [])
                headers = MutableHeaders(scope=message)
                if session.accessed:
                    headers.add_vary_header("Cookie")
                if session.modified and session:
                    # We have session data to persist.
                    data = self._signer.sign(session, time)
                    header_value: str = "{session_cookie}={data}; path={path}; {max_age}{security_flags}".format(
                        session_cookie=self.session_cookie,
                        data=data.decode("utf-8"),
                        path="/",
                        max_age=f"Max-Age={int(self.max_age.total_seconds())}; "
                        if self.max_age is not None
                        else "",
                        security_flags=self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)
                elif session.modified and not initial_session_was_empty:
                    # The session has been cleared.
                    header_value = "{session_cookie}={data}; path={path}; {expires}{security_flags}".format(
                        session_cookie=self.session_cookie,
                        data="null",
                        path="/",
                        expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
                        security_flags=self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)
