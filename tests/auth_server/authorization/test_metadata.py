import json
from http import HTTPStatus

from joserfc import jwk

from app_gateway.auth_server.authorization.metadata import (
    create_authorization_server_metadata_response,
    create_jwks_response,
)
from tests.auth_server.constants import ISSUER

PUBLIC_HEADERS = {
    "cache-control": "public, max-age=3600",
    "access-control-allow-origin": "*",
}


def test_create_authorization_server_metadata_response() -> None:
    response = create_authorization_server_metadata_response(
        ISSUER,
        f"{ISSUER}/oauth/authorize",
        f"{ISSUER}/oauth/token",
        f"{ISSUER}/oauth/device_authorization",
        f"{ISSUER}/oauth/jwks",
    )

    assert response.status_code == HTTPStatus.OK
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value
    assert json.loads(bytes(response.body)) == {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "device_authorization_endpoint": f"{ISSUER}/oauth/device_authorization",
        "jwks_uri": f"{ISSUER}/oauth/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "scopes_supported": ["openid", "profile", "email"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
    }


def test_create_jwks_response_omits_private_key(signing_key: jwk.Key) -> None:
    response = create_jwks_response(jwk.KeySet([signing_key]))

    assert response.status_code == HTTPStatus.OK
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value

    (key,) = json.loads(bytes(response.body))["keys"]
    assert "d" not in key
    assert key["kid"] == signing_key.kid
    assert key == signing_key.as_dict(private=False)
