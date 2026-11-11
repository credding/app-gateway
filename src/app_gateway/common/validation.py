from collections.abc import Sequence
from functools import lru_cache
from typing import Any, TypeForm

from pydantic import TypeAdapter, ValidationError


@lru_cache
def type_adapter[T](model: TypeForm[T]) -> TypeAdapter[T]:
    return TypeAdapter(model)


def validate_params[T](
    model: TypeForm[T],
    items: Sequence[tuple[str, Any]],
) -> T | ValidationError:
    grouped: dict[str, list[Any]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)

    try:
        return type_adapter(model).validate_python(
            {
                key: values[0] if len(values) == 1 else values
                for key, values in grouped.items()
            }
        )
    except ValidationError as e:
        return e
