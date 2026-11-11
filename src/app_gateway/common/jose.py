from datetime import datetime, timedelta
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric import ec
from joserfc import jwk, jwt

from app_gateway.crypto.key_management import (
    derive_private_bytes,
    normalize_time,
)


def get_token_signing_key(
    seed: bytes,
    time: datetime,
    rotation_schedule: timedelta,
) -> jwk.Key:
    return _get_token_signing_key(seed, normalize_time(time, rotation_schedule))


@lru_cache
def _get_token_signing_key(seed: bytes, time_norm: datetime) -> jwk.Key:
    private_bytes = derive_private_bytes(seed, time_norm)
    private_value = int.from_bytes(private_bytes, byteorder="big")

    key = jwk.ECKey.import_key(
        ec.derive_private_key(private_value, ec.SECP256R1()),
        jwk.KeyParameters(
            use="sig",
            alg="ES256",
        ),
    )
    key.ensure_kid()

    return key


def get_token_signing_keyset(
    seed: bytes,
    time: datetime,
    rotation_schedule: timedelta,
) -> jwk.KeySet:
    time_skewed = time + rotation_schedule / 2
    return _get_token_signing_keyset(
        seed,
        normalize_time(time_skewed, rotation_schedule),
        rotation_schedule,
    )


@lru_cache
def _get_token_signing_keyset(
    seed: bytes,
    time_norm: datetime,
    rotation_schedule: timedelta,
) -> jwk.KeySet:
    return jwk.KeySet(
        keys=[
            _get_token_signing_key(seed, time_norm - rotation_schedule),
            _get_token_signing_key(seed, time_norm),
        ]
    )


def encode_token(key: jwk.Key, token: jwt.Token) -> str:
    return jwt.encode(token.header, token.claims, key)


def decode_token(key: jwk.KeySet, value: str) -> jwt.Token:
    return jwt.decode(value, key)
