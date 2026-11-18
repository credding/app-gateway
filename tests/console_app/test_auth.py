import asyncio
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any

import pytest
from authlib.integrations.starlette_client import OAuthError
from fastapi import HTTPException, Request

from app_gateway.common.clock import to_timestamp
from app_gateway.console_app import auth
from app_gateway.console_app.auth import (
    REFRESH_WINDOW,
    get_session_token,
    needs_refresh,
    require_refreshed_user_id,
    set_session_token,
)
from app_gateway.console_app.schema import SessionToken
from app_gateway.settings import Settings

TIME = datetime(2026, 1, 1, tzinfo=UTC)
USER_ID = "usr_test"


def _request(session: dict[str, Any]) -> Request:
    return Request({"type": "http", "session": session})


def _token(expires_in: timedelta, refresh_token: str | None = "rt-old") -> SessionToken:
    return SessionToken(
        access_token="at-old",
        refresh_token=refresh_token,
        expires_at=to_timestamp(TIME + expires_in),
    )


def test_set_session_token_keeps_only_needed_fields() -> None:
    request = _request({})

    set_session_token(
        request,
        {
            "access_token": "at",
            "refresh_token": "rt",
            "expires_at": 123,
            "expires_in": 3600,
            "token_type": "Bearer",
            "id_token": "x" * 2000,
            "userinfo": {"picture": "x" * 400},
        },
    )

    assert request.session == {
        "token": {"access_token": "at", "refresh_token": "rt", "expires_at": 123}
    }


def test_get_session_token_reads_legacy_full_token() -> None:
    request = _request({"token": {"access_token": "at", "id_token": "x"}})

    assert get_session_token(request) == SessionToken(access_token="at")


@pytest.mark.parametrize("value", [None, "garbage", {"refresh_token": "rt"}])
def test_get_session_token_invalid(value: object) -> None:
    session = {} if value is None else {"token": value}

    assert get_session_token(_request(session)) is None


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (_token(REFRESH_WINDOW + timedelta(seconds=1)), False),
        (_token(REFRESH_WINDOW), True),
        (_token(-timedelta(minutes=1)), True),
        (_token(-timedelta(minutes=1), refresh_token=None), False),
        (SessionToken(access_token="at", refresh_token="rt"), False),
    ],
    ids=["fresh", "at-window", "expired", "no-refresh-token", "no-expiry"],
)
def test_needs_refresh(token: SessionToken, expected: bool) -> None:
    assert needs_refresh(token, TIME) is expected


class _FakeClient:
    def __init__(self, result: dict[str, Any] | Exception) -> None:
        self.result = result
        self.calls: list[dict[str, str | None]] = []

    async def fetch_access_token(self, **kwargs: str | None) -> dict[str, Any]:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def validated(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def fake_validate(access_token: str, _settings: Settings, _time: datetime) -> str:
        seen.append(access_token)
        return USER_ID

    monkeypatch.setattr(auth, "now", lambda: TIME)
    monkeypatch.setattr(auth, "validate_access_token", fake_validate)
    return seen


def _install_client(monkeypatch: pytest.MonkeyPatch, client: _FakeClient) -> None:
    monkeypatch.setattr(auth, "get_oauth_client", lambda: client)


def _run(request: Request) -> str:
    return asyncio.run(
        require_refreshed_user_id(request, settings=Settings.model_construct())
    )


def test_refreshed_user_id_skips_refresh_when_fresh(
    monkeypatch: pytest.MonkeyPatch, validated: list[str]
) -> None:
    client = _FakeClient(RuntimeError("should not be called"))
    _install_client(monkeypatch, client)
    request = _request({"token": _token(timedelta(hours=1)).model_dump()})

    assert _run(request) == USER_ID
    assert client.calls == []
    assert validated == ["at-old"]


def test_refreshed_user_id_refreshes_near_expiry(
    monkeypatch: pytest.MonkeyPatch, validated: list[str]
) -> None:
    client = _FakeClient(
        {"access_token": "at-new", "refresh_token": "rt-new", "expires_at": 999}
    )
    _install_client(monkeypatch, client)
    request = _request({"token": _token(timedelta(minutes=1)).model_dump()})

    assert _run(request) == USER_ID
    assert client.calls == [{"grant_type": "refresh_token", "refresh_token": "rt-old"}]
    assert validated == ["at-new"]
    assert request.session["token"] == {
        "access_token": "at-new",
        "refresh_token": "rt-new",
        "expires_at": 999,
    }


def test_refreshed_user_id_clears_session_when_refresh_rejected(
    monkeypatch: pytest.MonkeyPatch, validated: list[str]
) -> None:
    _install_client(monkeypatch, _FakeClient(OAuthError(error="invalid_grant")))
    request = _request({"token": _token(timedelta(minutes=1)).model_dump()})

    with pytest.raises(HTTPException) as exc_info:
        _run(request)

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED
    assert "token" not in request.session
    assert validated == []


@pytest.mark.usefixtures("validated")
def test_refreshed_user_id_requires_token() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _run(_request({}))

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED
