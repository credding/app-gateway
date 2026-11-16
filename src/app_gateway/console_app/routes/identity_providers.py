from fastapi import APIRouter, Depends, Response

from app_gateway.console_app import app_manager
from app_gateway.console_app.app_schema import ListIdpsView
from app_gateway.console_app.auth import require_user_id


def _no_store(response: Response) -> None:
    response.headers["cache-control"] = "no-store"


router = APIRouter(
    prefix="/api/identity-providers",
    dependencies=[Depends(_no_store), Depends(require_user_id)],
)


@router.get("")
async def list_identity_providers() -> ListIdpsView:
    return ListIdpsView(identity_providers=await app_manager.list_idps())
