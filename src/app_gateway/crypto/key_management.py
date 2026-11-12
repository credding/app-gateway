import struct
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app_gateway.common.clock import EPOCH, to_timestamp


def normalize_time(time: datetime, schedule: timedelta) -> datetime:
    unix_time = time - EPOCH
    return time - (unix_time % schedule)


def derive_private_bytes(seed: bytes, time_norm: datetime) -> bytes:
    info = struct.pack(">Q", to_timestamp(time_norm))
    hkdf = HKDF(SHA256(), 32, None, info)
    return hkdf.derive(seed)


# FIPS 186-5 Section A.2.1
def derive_p256_private_value(seed: bytes, time_norm: datetime) -> int:
    info: bytes = struct.pack(">Q", to_timestamp(time_norm))
    hkdf = HKDF(SHA256(), 44, None, info)
    x = hkdf.derive(seed)
    n = int.from_bytes(x, "big")
    return n % (ec.SECP256R1().group_order - 1) + 1
