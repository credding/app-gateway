from collections.abc import Sequence
from functools import lru_cache
from typing import Any, TypeForm

from pydantic import BaseModel, TypeAdapter


@lru_cache
def type_adapter[T](model: TypeForm[T]) -> TypeAdapter[T]:
    return TypeAdapter(model)


def validate_params[T: BaseModel](
    model: type[T],
    items: Sequence[tuple[str, Any]],
) -> T:
    grouped: dict[str, list[Any]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)

    return model.model_validate(
        {
            key: values[0] if len(values) == 1 else values
            for key, values in grouped.items()
        }
    )
