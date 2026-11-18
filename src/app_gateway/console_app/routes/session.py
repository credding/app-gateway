from fastapi import APIRouter, Depends, Response

from app_gateway.console_app.auth import RefreshedUserId
from app_gateway.console_app.schema import SessionView


def _no_store(response: Response) -> None:
    response.headers["cache-control"] = "no-store"


router = APIRouter(prefix="/api/session", dependencies=[Depends(_no_store)])


@router.get("")
async def get_session(user_id: RefreshedUserId) -> SessionView:
    return SessionView(user_id=user_id)
