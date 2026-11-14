from fastapi import Response
from fastapi.responses import JSONResponse
from joserfc import jwk

from app_gateway.oauth import (
    AuthorizationServerMetadata,
    CodeChallengeMethod,
    GrantType,
    ResponseType,
)
from app_gateway.oauth.responses import OauthResponse

_PUBLIC_HEADERS = {
    "cache-control": "public, max-age=3600",
    "access-control-allow-origin": "*",
}


def create_authorization_server_metadata_response(
    issuer: str,
    authorization_endpoint: str,
    token_endpoint: str,
    jwks_uri: str,
) -> Response:
    return OauthResponse(
        AuthorizationServerMetadata(
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            response_types_supported=[ResponseType.CODE],
            grant_types_supported=[
                GrantType.AUTHORIZATION_CODE,
                GrantType.REFRESH_TOKEN,
            ],
            token_endpoint_auth_methods_supported=[
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            code_challenge_methods_supported=[CodeChallengeMethod.S256],
            authorization_response_iss_parameter_supported=True,
        ),
        headers=_PUBLIC_HEADERS,
    )


def create_jwks_response(keyset: jwk.KeySet) -> Response:
    return JSONResponse(
        keyset.as_dict(private=False),
        headers=_PUBLIC_HEADERS,
    )
