import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_nonce() -> bytes:
    return os.urandom(12)


def create_associated_data(*data: str) -> bytes:
    return b"".join(_length_prefix(arg) for arg in data)


def _length_prefix(s: str) -> bytes:
    data = s.encode("utf-8")
    n = len(data)
    return struct.pack(f">H{n}s", n, data)


def encrypt_data(
    key: bytes,
    nonce: bytes,
    data: bytes,
    associated_data: bytes,
) -> bytes:
    aesgcm = AESGCM(key)
    return nonce + aesgcm.encrypt(nonce, data, associated_data)


def decrypt_data(
    key: bytes,
    data_enc: bytes,
    associated_data: bytes,
) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(data_enc[:12], data_enc[12:], associated_data)
