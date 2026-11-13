from collections.abc import Sequence
from typing import Any, TypeForm

from app_gateway.common.validation import type_adapter

type FormParams = Sequence[tuple[str, Any]]


def validate_params[T](model: TypeForm[T], items: FormParams) -> T:
    grouped: dict[str, list[Any]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)

    return type_adapter(model).validate_python(
        {
            key: values[0] if len(values) == 1 else values
            for key, values in grouped.items()
        }
    )
