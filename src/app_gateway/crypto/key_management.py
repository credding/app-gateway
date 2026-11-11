import struct
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app_gateway.common.clock import EPOCH


def normalize_time(time: datetime, schedule: timedelta) -> datetime:
    unix_time = time - EPOCH
    return time - (unix_time % schedule)


def derive_private_bytes(key_material: bytes, time_norm: datetime) -> bytes:
    info = struct.pack(">Q", int(time_norm.timestamp()))
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(key_material)
