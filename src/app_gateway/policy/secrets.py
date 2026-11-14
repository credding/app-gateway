from app_gateway.crypto.encrypt import (
    create_associated_data,
    decrypt_data,
    encrypt_data,
)
from app_gateway.policy.schema import AppIdentityProvider

_APP_IDP_CLIENT_SECRET = "app_idp_client_secret"


def _app_idp_client_secret_ad(app_id: str, idp_id: str) -> bytes:
    return create_associated_data(_APP_IDP_CLIENT_SECRET, app_id, idp_id)


def encrypt_app_idp_client_secret(
    key: bytes,
    nonce: bytes,
    app_id: str,
    idp_id: str,
    client_secret: str,
) -> bytes:
    return encrypt_data(
        key,
        nonce,
        client_secret.encode(),
        _app_idp_client_secret_ad(app_id, idp_id),
    )


def decrypt_app_idp_client_secret(
    key: bytes,
    app_idp: AppIdentityProvider,
) -> str:
    return decrypt_data(
        key,
        app_idp.client_secret_enc,
        _app_idp_client_secret_ad(app_idp.app_id, app_idp.idp_id),
    ).decode()
