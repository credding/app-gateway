import base64
from typing import TypedDict


class _B64UrlKwargs(TypedDict):
    altchars: bytes
    padded: bool


class _B64DecodeKwargs(TypedDict):
    ignorechars: bytes
    canonical: bool


_B64URL_KWARGS = _B64UrlKwargs(altchars=b"-_", padded=False)
_B64DECODE_KWARGS = _B64DecodeKwargs(ignorechars=b"", canonical=True)


def base64encode(s: bytes) -> bytes:
    return base64.b64encode(s)


def base64decode(s: bytes) -> bytes:
    return base64.b64decode(s, **_B64DECODE_KWARGS)


def base64urlencode(s: bytes) -> bytes:
    return base64.b64encode(s, **_B64URL_KWARGS)


def base64urldecode(s: bytes) -> bytes:
    return base64.b64decode(s, **_B64URL_KWARGS, **_B64DECODE_KWARGS)
