from typing import Any

from pydantic import BaseModel


class ConsoleSession(BaseModel):
    token: Any
