from collections.abc import Sequence
from functools import lru_cache
from typing import Any, TypeForm

from pydantic import TypeAdapter


@lru_cache
def type_adapter[T](model: TypeForm[T]) -> TypeAdapter[T]:
    return TypeAdapter(model)


type FormParamsItems = Sequence[tuple[str, Any]]
type FormParams = dict[str, Any]


def parse_form_params(items: FormParamsItems) -> FormParams:
    grouped: dict[str, list[Any]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)
    return {
        key: values[0] if len(values) == 1 else values
        for key, values in grouped.items()
    }


def parse_form_params_str(params: FormParams, key: str) -> str | None:
    value = params.get(key)
    if isinstance(value, str):
        return value
    return value


def validate_params[T](model: TypeForm[T], items: FormParamsItems) -> T:
    grouped: dict[str, list[Any]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)

    return type_adapter(model).validate_python(
        {
            key: values[0] if len(values) == 1 else values
            for key, values in grouped.items()
        }
    )
