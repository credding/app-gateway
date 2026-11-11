from datetime import UTC, datetime

EPOCH = datetime.fromtimestamp(0, UTC)


def now() -> datetime:
    return datetime.now(UTC)


def to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


def to_timestamp(dt: datetime) -> int:
    return int(dt.timestamp())
