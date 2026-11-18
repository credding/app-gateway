from datetime import UTC, datetime, timedelta

import pytest
from itsdangerous import SignatureExpired
from pydantic import BaseModel

from app_gateway.common.cookies import Signer

TIME = datetime(2026, 1, 1, tzinfo=UTC)
MAX_AGE = timedelta(hours=1)
SEED = b"test-cookie-signing-seed-0123456789"
ROTATION = timedelta(days=30)


class Value(BaseModel):
    data: str


def _signer(max_age: timedelta | None = MAX_AGE) -> Signer[Value]:
    return Signer(Value, "test", SEED, ROTATION, max_age)


@pytest.mark.parametrize(
    "age",
    [timedelta(), timedelta(seconds=1), MAX_AGE - timedelta(seconds=1)],
    ids=["same-instant", "one-second", "just-before-max-age"],
)
def test_unsign_within_max_age(age: timedelta) -> None:
    signer = _signer()

    assert signer.unsign(signer.sign(Value(data="x"), TIME), TIME + age) == Value(
        data="x"
    )


@pytest.mark.parametrize(
    "age",
    [MAX_AGE, MAX_AGE + timedelta(seconds=1), -timedelta(seconds=1)],
    ids=["at-max-age", "past-max-age", "signed-in-future"],
)
def test_unsign_outside_max_age(age: timedelta) -> None:
    signer = _signer()
    signed = signer.sign(Value(data="x"), TIME)

    with pytest.raises(SignatureExpired):
        signer.unsign(signed, TIME + age)


def test_unsign_without_max_age() -> None:
    signer = _signer(max_age=None)
    signed = signer.sign(Value(data="x"), TIME)

    assert signer.unsign(signed, TIME + ROTATION) == Value(data="x")


def test_unsign_expiry_uses_given_time_not_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _signer()
    signed = signer.sign(Value(data="x"), TIME)

    # Wall clock has moved well past max_age; the given time hasn't.
    wall_clock = datetime.now(UTC) + 10 * MAX_AGE
    monkeypatch.setattr("itsdangerous.timed.time.time", wall_clock.timestamp)

    assert signer.unsign(signed, TIME + timedelta(minutes=30)) == Value(data="x")
