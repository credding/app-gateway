import hashlib
import struct
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Annotated, Literal

from fastapi import Depends, Request, Response
from itsdangerous import SignatureExpired, TimestampSigner
from pydantic import BaseModel, TypeAdapter

from app_gateway.common.base64 import base64urldecode, base64urlencode
from app_gateway.common.clock import to_datetime, to_timestamp
from app_gateway.common.validation import type_adapter
from app_gateway.crypto.key_management import derive_private_bytes, normalize_time
from app_gateway.settings import Settings, get_settings


class Cookie[T: BaseModel]:
    def __init__(
        self,
        model: type[T],
        name: str,
        max_age: timedelta | None = None,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        self._model = model
        self._name = name
        self._max_age = max_age
        self._samesite = samesite

    def __call__(
        self,
        settings: Annotated[Settings, Depends(get_settings)],
        request: Request,
    ) -> RequestCookie[T]:
        return RequestCookie(
            self._model, self._name, request, settings, self._max_age, self._samesite
        )


class RequestCookie[T: BaseModel]:
    def __init__(
        self,
        model: type[T],
        name: str,
        request: Request,
        settings: Settings,
        max_age: timedelta | None,
        samesite: Literal["lax", "strict", "none"],
    ) -> None:
        self._request = request
        self._signer = Signer(
            model,
            name,
            settings.cookie_signing_key_seed.get_secret_value(),
            settings.key_rotation_schedule,
            max_age,
        )
        self._samesite = samesite

    def get_cookie(self, time: datetime) -> T | None:
        signed_value = self._request.cookies.get(self._signer.cookie)
        if signed_value is None:
            return None

        return self._signer.unsign(signed_value, time)

    def set_cookie(self, response: Response, value: T, time: datetime) -> None:
        signed_value = self._signer.sign(value, time)

        response.set_cookie(
            self._signer.cookie,
            signed_value.decode(),
            max_age=self._signer.max_age,
            secure=True,
            httponly=True,
            samesite=self._samesite,
            partitioned=self._samesite == "none",
        )

    def delete_cookie(self, response: Response) -> None:
        response.delete_cookie(
            self._signer.cookie,
            secure=True,
            samesite=self._samesite,
            partitioned=self._samesite == "none",
        )


class Signer[T]:
    def __init__(
        self,
        typ: type[T],
        name: str,
        cookie_signing_key_seed: bytes,
        key_rotation_schedule: timedelta,
        max_age: timedelta | None,
    ) -> None:
        self._type_adapter: TypeAdapter[T] = type_adapter(typ)
        self._name = name
        self._cookie_signing_key_seed = cookie_signing_key_seed
        self._key_rotation_schedule = key_rotation_schedule
        self._max_age = max_age

        self.cookie = f"__Host-{name}"
        self.max_age = int(max_age.total_seconds()) if max_age is not None else None

    def sign(self, value: T, time: datetime) -> bytes:
        cookie_json = self._type_adapter.dump_json(value)
        cookie_base64 = base64urlencode(cookie_json)

        timestamp_bytes = _pack_timestamp(time)
        timestamp_base64 = base64urlencode(timestamp_bytes)

        signer = self._get_cookie_signer(time)
        cookie_payload = _pack_cookie(cookie_base64, timestamp_base64)
        return signer.sign(cookie_payload)

    def unsign(self, signed_value: str | bytes, time: datetime) -> T:
        signer = self._get_cookie_signer(time)
        cookie_payload = signer.unsign(signed_value, self.max_age)
        cookie_base64, timestamp_base64 = _unpack_cookie(cookie_payload)

        timestamp_bytes = base64urldecode(timestamp_base64)
        timestamp = _unpack_timestamp(timestamp_bytes)
        self._check_age(time, timestamp)

        cookie_json = base64urldecode(cookie_base64)
        return self._type_adapter.validate_json(cookie_json)

    def _get_cookie_signer(self, time: datetime) -> TimestampSigner:
        return get_cookie_signer(
            self._cookie_signing_key_seed,
            time,
            self._key_rotation_schedule,
            self._name,
        )

    def _check_age(self, time: datetime, timestamp: datetime) -> None:
        if self._max_age is None:
            return
        age = time - timestamp
        if timedelta() < age < self._max_age:
            return
        raise SignatureExpired


def _pack_cookie(cookie_base64: bytes, timestamp_base64: bytes) -> bytes:
    return b".".join([cookie_base64, timestamp_base64])


def _unpack_cookie(cookie_unsigned: bytes) -> tuple[bytes, bytes]:
    cookie_base64, _, timestamp_base64 = cookie_unsigned.partition(b".")
    return cookie_base64, timestamp_base64


def _pack_timestamp(timestamp: datetime) -> bytes:
    return struct.pack(">Q", to_timestamp(timestamp)).lstrip(b"\x00")


def _unpack_timestamp(timestamp_bytes: bytes) -> datetime:
    (timestamp,) = struct.unpack(">Q", timestamp_bytes.rjust(8, b"\x00"))
    return to_datetime(timestamp)


def get_cookie_signer(
    seed: bytes,
    time: datetime,
    rotation_schedule: timedelta,
    salt: str,
) -> TimestampSigner:
    return _get_cookie_signer(
        seed,
        normalize_time(time, rotation_schedule),
        rotation_schedule,
        salt,
    )


@lru_cache
def _get_cookie_signer(
    seed: bytes,
    time_norm: datetime,
    rotation_schedule: timedelta,
    salt: str,
) -> TimestampSigner:
    return TimestampSigner(
        secret_key=[
            derive_private_bytes(seed, time_norm - rotation_schedule),
            derive_private_bytes(seed, time_norm),
        ],
        salt=salt,
        digest_method=hashlib.sha256,
    )
