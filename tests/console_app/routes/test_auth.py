from http import HTTPStatus

from fastapi.testclient import TestClient

from app_gateway.console_app.app import app


def test_logout_redirects_home() -> None:
    client = TestClient(app, base_url="https://localhost")

    response = client.post("/api/auth/logout", follow_redirects=False)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/"
