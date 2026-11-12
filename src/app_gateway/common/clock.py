from datetime import UTC, datetime, timedelta
from typing import overload

EPOCH = datetime.fromtimestamp(0, UTC)


def now() -> datetime:
    return datetime.now(UTC)


@overload
def to_timestamp(dt: datetime) -> int: ...
@overload
def to_timestamp(dt: datetime | None) -> int | None: ...
def to_timestamp(dt: datetime | None) -> int | None:
    return None if dt is None else int(dt.timestamp())


def to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


@overload
def to_seconds(td: timedelta) -> int: ...
@overload
def to_seconds(td: timedelta | None) -> int | None: ...
def to_seconds(td: timedelta | None) -> int | None:
    return None if td is None else int(td.total_seconds())


def to_timedelta(seconds: int) -> timedelta:
    return timedelta(seconds=seconds)
