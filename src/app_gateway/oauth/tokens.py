import secrets

from app_gateway.common.base64 import base64urldecode, base64urlencode
from app_gateway.common.tokens import (
    generate_id_token,
    generate_secret_token,
    hash_token,
    verify_token,
)


def generate_confidential_client_id() -> str:
    return generate_id_token("svc_")


def generate_public_client_id() -> str:
    return generate_id_token("pub_")


def generate_client_secret() -> str:
    return generate_secret_token()


def generate_code_verifier() -> str:
    return generate_secret_token()


def generate_state_token() -> str:
    return generate_secret_token()


def generate_authorization_code() -> str:
    return generate_secret_token()


def generate_refresh_token() -> str:
    return generate_secret_token()


def generate_device_code() -> str:
    return generate_secret_token()


# RFC 8628 Section 6.1: base-20 charset, 8 characters (~34.5 bits of entropy).
_USER_CODE_CHARSET = "BCDFGHJKLMNPQRSTVWXZ"
_USER_CODE_LENGTH = 8


def generate_user_code() -> str:
    code = "".join(secrets.choice(_USER_CODE_CHARSET) for _ in range(_USER_CODE_LENGTH))
    return f"{code[:4]}-{code[4:]}"


def normalize_user_code(user_code: str) -> str:
    # RFC 8628 Section 6.1: compare case-insensitively, ignoring punctuation.
    return "".join(c for c in user_code.upper() if c.isalnum())


def compute_code_challenge(code_verifier: str) -> str:
    return base64urlencode(hash_token(code_verifier)).decode()


def verify_code_challenge(code_verifier: str, code_challenge: str) -> bool:
    return verify_token(code_verifier, base64urldecode(code_challenge.encode()))
