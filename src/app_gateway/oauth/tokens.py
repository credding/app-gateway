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


def compute_code_challenge(code_verifier: str) -> str:
    return base64urlencode(hash_token(code_verifier)).decode()


def verify_code_challenge(code_verifier: str, code_challenge: str) -> bool:
    return verify_token(code_verifier, base64urldecode(code_challenge.encode()))
