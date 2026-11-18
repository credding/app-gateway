import re

import pytest

from app_gateway.oauth import generate_user_code, normalize_user_code


def test_generate_user_code() -> None:
    code = generate_user_code()
    assert re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}", code)


@pytest.mark.parametrize(
    "entered", ["BCDF-GHJK", "bcdfghjk", " bcdf ghjk ", "B-C-D-F-G-H-J-K"]
)
def test_normalize_user_code(entered: str) -> None:
    assert normalize_user_code(entered) == "BCDFGHJK"
