from datetime import datetime

from pydantic import BaseModel

from app_gateway.console_app.app_schema import ResourceView


class OwnerView(BaseModel):
    user_id: str
    name: str | None
    pronouns: str | None


class CatalogApp(BaseModel):
    app_id: str
    slug: str
    name: str
    owners: list[OwnerView]
    resources: list[ResourceView]
    is_owner: bool
    created_at: datetime
    updated_at: datetime


class ListCatalogView(BaseModel):
    apps: list[CatalogApp]
