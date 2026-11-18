from fastapi import Request, Response
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader, PackageLoader

from app_gateway.auth_server.authorization.device_authorization import DevicePage
from app_gateway.settings import SETTINGS_DIR

templates = Jinja2Templates(
    env=Environment(
        loader=ChoiceLoader(
            [
                FileSystemLoader(SETTINGS_DIR / "branding/templates"),
                PackageLoader("app_gateway.default_branding", "templates"),
            ]
        ),
        autoescape=True,
    )
)


def render_device_page(
    request: Request, page: DevicePage, user_code: str | None = None
) -> Response:
    return templates.TemplateResponse(
        request,
        name="device.html",
        context={"page": page, "user_code": user_code},
        status_code=400 if page in {DevicePage.INVALID_CODE, DevicePage.ERROR} else 200,
        headers={"cache-control": "no-store"},
    )
