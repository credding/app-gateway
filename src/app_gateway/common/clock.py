from datetime import UTC, datetime

EPOCH = datetime.fromtimestamp(0, UTC)


def now() -> datetime:
    return datetime.now(UTC)
