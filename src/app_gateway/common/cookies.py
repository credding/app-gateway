import hashlib
import struct
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request, Response
from itsdangerous import Signer
from pydantic import BaseModel

from app_gateway.common.base64 import base64urldecode, base64urlencode
from app_gateway.crypto.key_management import (
    derive_private_bytes,
    normalize_time,
)
from app_gateway.settings import Settings, get_settings


class Cookie[T: BaseModel]:
    def __init__(
        self,
        model: type[T],
        name: str,
        max_age: timedelta | None = None,
    ) -> None:
        self._model = model
        self._name = f"__Host-{name}"
        self._max_age = max_age

    def __call__(
        self,
        settings: Annotated[Settings, Depends(get_settings)],
        request: Request,
        response: Response,
    ) -> RequestCookie[T]:
        return RequestCookie(
            self._model,
            self._name,
            request,
            response,
            settings,
            self._max_age,
        )


class RequestCookie[T: BaseModel]:
    def __init__(
        self,
        model: type[T],
        name: str,
        request: Request,
        response: Response,
        settings: Settings,
        max_age: timedelta | None,
    ) -> None:
        self._model = model
        self._name = name
        self._request = request
        self._response = response
        self._settings = settings
        self._max_age = max_age

    def get_cookie(self, time: datetime) -> T | None:
        cookie_signed = self._request.cookies.get(self._name)
        if cookie_signed is None:
            return None

        signer = self._get_cookie_signer(time)
        cookie_payload = signer.unsign(cookie_signed)
        cookie_base64, timestamp_base64 = _unpack_cookie(cookie_payload)

        timestamp_bytes = base64urldecode(timestamp_base64)
        timestamp = _unpack_timestamp(timestamp_bytes)
        self._check_age(time, timestamp)

        cookie_json = base64urldecode(cookie_base64)
        return self._model.model_validate_json(cookie_json)

    def set_cookie(self, value: T, time: datetime) -> None:
        cookie_json = self._model.model_dump_json(value)
        cookie_base64 = base64urlencode(cookie_json.encode())

        timestamp_bytes = _pack_timestamp(time)
        timestamp_base64 = base64urlencode(timestamp_bytes)

        signer = self._get_cookie_signer(time)
        cookie_payload = _pack_cookie(cookie_base64, timestamp_base64)
        cookie_signed = signer.sign(cookie_payload)

        self._response.set_cookie(
            self._name,
            cookie_signed.decode(),
            max_age=self._get_max_age(),
            secure=True,
            httponly=True,
            samesite="none",
            partitioned=True,
        )

    def delete_cookie(self) -> None:
        self._response.delete_cookie(
            self._name,
            secure=True,
            samesite="none",
            partitioned=True,
        )

    def _get_cookie_signer(self, time: datetime) -> Signer:
        return get_cookie_signer(
            self._settings.cookie_signing_key_seed.get_secret_value(),
            time,
            self._settings.key_rotation_schedule,
            self._name,
        )

    def _check_age(self, time: datetime, timestamp: datetime) -> None:
        if self._max_age is None:
            return
        age = time - timestamp
        if timedelta() < age < self._max_age:
            return
        raise ValueError

    def _get_max_age(self) -> int | None:
        if self._max_age is None:
            return None
        return int(self._max_age.total_seconds())


def _pack_cookie(cookie_base64: bytes, timestamp_base64: bytes) -> bytes:
    return b".".join([cookie_base64, timestamp_base64])


def _unpack_cookie(cookie_unsigned: bytes) -> tuple[bytes, bytes]:
    cookie_base64, _, timestamp_base64 = cookie_unsigned.partition(b".")
    return cookie_base64, timestamp_base64


def _pack_timestamp(timestamp: datetime) -> bytes:
    return struct.pack(">Q", int(timestamp.timestamp())).lstrip(b"\x00")


def _unpack_timestamp(timestamp_bytes: bytes) -> datetime:
    (timestamp,) = struct.unpack(">Q", timestamp_bytes.rjust(8, b"\x00"))
    return datetime.fromtimestamp(timestamp, UTC)


def get_cookie_signer(
    seed: bytes,
    time: datetime,
    rotation_schedule: timedelta,
    salt: str,
) -> Signer:
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
) -> Signer:
    return Signer(
        secret_key=[
            derive_private_bytes(seed, time_norm - rotation_schedule),
            derive_private_bytes(seed, time_norm),
        ],
        salt=salt,
        digest_method=hashlib.sha256,
    )
