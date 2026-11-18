from pydantic import BaseModel


class SessionToken(BaseModel):
    access_token: str
    refresh_token: str | None = None
    expires_at: int | None = None


class SessionView(BaseModel):
    user_id: str
