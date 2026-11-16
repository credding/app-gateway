from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app_gateway.console_app import app_manager
from app_gateway.console_app.app_schema import (
    AppCreate,
    AppIdpUpdate,
    AppIdpView,
    AppUpdate,
    AppView,
    ClientCreate,
    ClientSecretView,
    ClientUpdate,
    ClientView,
    ListAppsView,
    ResourceCreate,
    ResourceUpdate,
    ResourceView,
)
from app_gateway.console_app.auth import UserId
from app_gateway.settings import Settings, get_settings

type AppSettings = Annotated[Settings, Depends(get_settings)]


def _no_store(response: Response) -> None:
    response.headers["cache-control"] = "no-store"


router = APIRouter(prefix="/api/apps", dependencies=[Depends(_no_store)])


@router.get("")
async def list_apps(user_id: UserId) -> ListAppsView:
    return ListAppsView(apps=await app_manager.list_apps(user_id))


@router.post("", status_code=201)
async def create_app(
    user_id: UserId,
    body: AppCreate,
) -> AppView:
    return await app_manager.create_app(user_id, body)


@router.patch("/{app_id}")
async def update_app(
    user_id: UserId,
    app_id: str,
    body: AppUpdate,
) -> AppView:
    return await app_manager.update_app(user_id, app_id, body)


@router.delete("/{app_id}", status_code=204)
async def delete_app(
    user_id: UserId,
    app_id: str,
) -> None:
    await app_manager.delete_app(user_id, app_id)


@router.put("/{app_id}/idps/{idp_id}")
async def update_app_idp(
    user_id: UserId,
    settings: AppSettings,
    app_id: str,
    idp_id: str,
    body: AppIdpUpdate,
) -> AppIdpView:
    return await app_manager.put_app_idp(
        user_id,
        app_id,
        idp_id,
        body,
        settings.secret_encryption_key.get_secret_value(),
    )


@router.delete("/{app_id}/idps/{idp_id}", status_code=204)
async def delete_app_idp(
    user_id: UserId,
    app_id: str,
    idp_id: str,
) -> None:
    await app_manager.delete_app_idp(user_id, app_id, idp_id)


@router.post("/{app_id}/clients", status_code=201)
async def create_client(
    user_id: UserId,
    app_id: str,
    body: ClientCreate,
) -> ClientSecretView:
    return await app_manager.create_client(user_id, app_id, body)


@router.patch("/{app_id}/clients/{client_id}")
async def update_client(
    user_id: UserId,
    app_id: str,
    client_id: str,
    body: ClientUpdate,
) -> ClientView:
    return await app_manager.update_client(user_id, app_id, client_id, body)


@router.post("/{app_id}/clients/{client_id}/client-secret")
async def rotate_client_secret(
    user_id: UserId,
    app_id: str,
    client_id: str,
) -> ClientSecretView:
    return await app_manager.rotate_client_secret(user_id, app_id, client_id)


@router.delete("/{app_id}/clients/{client_id}", status_code=204)
async def delete_client(
    user_id: UserId,
    app_id: str,
    client_id: str,
) -> None:
    await app_manager.delete_client(user_id, app_id, client_id)


@router.post("/{app_id}/resources", status_code=201)
async def create_resource(
    user_id: UserId,
    app_id: str,
    body: ResourceCreate,
) -> ResourceView:
    return await app_manager.create_resource(user_id, app_id, body)


@router.patch("/{app_id}/resources/{resource_id}")
async def update_resource(
    user_id: UserId,
    app_id: str,
    resource_id: str,
    body: ResourceUpdate,
) -> ResourceView:
    return await app_manager.update_resource(user_id, app_id, resource_id, body)


@router.delete("/{app_id}/resources/{resource_id}", status_code=204)
async def delete_resource(
    user_id: UserId,
    app_id: str,
    resource_id: str,
) -> Response:
    await app_manager.delete_resource(user_id, app_id, resource_id)
    return Response(status_code=204)
