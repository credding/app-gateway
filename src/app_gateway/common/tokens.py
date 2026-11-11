import hashlib
import hmac
import os
import secrets

from app_gateway.common.base64 import base64encode, base64urlencode


def _generate_secret_bytes() -> bytes:
    return os.urandom(32)


def generate_secret_key() -> str:
    return base64encode(_generate_secret_bytes()).decode()


def generate_id_token(prefix: str = "") -> str:
    return prefix + secrets.token_hex(16)


def generate_secret_token() -> str:
    return base64urlencode(_generate_secret_bytes()).decode()


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def verify_token(token: str, token_hash: bytes) -> bool:
    return hmac.compare_digest(hash_token(token), token_hash)
