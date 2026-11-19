from http import HTTPStatus

from fastapi.testclient import TestClient

from app_gateway.auth_server.app import app

ORIGIN = "https://example.com"


def test_cors_preflight_allows_any_origin() -> None:
    client = TestClient(app, base_url="https://localhost")

    response = client.options(
        "/oauth/token",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )

    assert response.status_code == HTTPStatus.OK
    assert response.headers["access-control-allow-origin"] == "*"
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "access-control-allow-credentials" not in response.headers


def test_cors_simple_request_allows_any_origin() -> None:
    client = TestClient(app, base_url="https://localhost")

    response = client.get(
        "/.well-known/openid-configuration", headers={"Origin": ORIGIN}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers
