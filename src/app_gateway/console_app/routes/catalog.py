from fastapi import APIRouter, Depends, Response

from app_gateway.console_app import catalog_manager
from app_gateway.console_app.auth import UserId
from app_gateway.console_app.catalog_schema import CatalogApp, ListCatalogView


def _no_store(response: Response) -> None:
    response.headers["cache-control"] = "no-store"


router = APIRouter(prefix="/api/catalog", dependencies=[Depends(_no_store)])


@router.get("/apps")
async def list_catalog_apps(user_id: UserId) -> ListCatalogView:
    return ListCatalogView(apps=await catalog_manager.list_catalog(user_id))


@router.get("/apps/{app_slug}")
async def get_catalog_app(user_id: UserId, app_slug: str) -> CatalogApp:
    return await catalog_manager.get_catalog_app(user_id, app_slug)
