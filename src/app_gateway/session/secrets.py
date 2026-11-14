from app_gateway.crypto.encrypt import (
    create_associated_data,
    decrypt_data,
    encrypt_data,
)
from app_gateway.session.schema import IdpSession

_IDP_TOKEN = "idp_token"


def _idp_refresh_token_ad(client_id: str, user_id: str, idp_issuer: str) -> bytes:
    return create_associated_data(_IDP_TOKEN, client_id, user_id, idp_issuer)


def encrypt_idp_refresh_token(
    key: bytes,
    nonce: bytes,
    client_id: str,
    user_id: str,
    idp_issuer: str,
    refresh_token: str,
) -> bytes:
    return encrypt_data(
        key,
        nonce,
        refresh_token.encode(),
        _idp_refresh_token_ad(client_id, user_id, idp_issuer),
    )


def decrypt_idp_refresh_token(
    key: bytes,
    idp_session: IdpSession,
) -> str | None:
    if idp_session.refresh_token_enc is None:
        return None
    return decrypt_data(
        key,
        idp_session.refresh_token_enc,
        _idp_refresh_token_ad(
            idp_session.client_id, idp_session.user_id, idp_session.idp_issuer
        ),
    ).decode()
