import json
from typing import Any, NamedTuple

from app_gateway.common.http import get_http_client
from app_gateway.oauth import TokenRequest, TokenResponse
from app_gateway.policy import IdentityProvider


async def request_idp_token(
    idp: IdentityProvider, request: TokenRequest
) -> TokenResponse:
    response = await get_http_client().post(
        idp.token_endpoint,
        data=request.model_dump(mode="json", exclude_none=True),
    )
    response.raise_for_status()
    return TokenResponse.model_validate_json(response.content)


async def request_idp_userinfo(
    idp: IdentityProvider, access_token: str
) -> dict[str, Any]:
    response = await get_http_client().get(
        idp.userinfo_endpoint,
        headers={"authorization": f"Bearer {access_token}"},
    )
    response.raise_for_status()
    return json.loads(response.content)


class UserinfoClaimsResult(NamedTuple):
    idp_subject: str
    claims: dict[str, Any]


def map_userinfo_claims(
    idp: IdentityProvider, idp_claims: dict[str, Any]
) -> UserinfoClaimsResult:
    claims = {
        name: idp_claims[idp_name] for name, idp_name in idp.userinfo_claims_map.items()
    }
    return UserinfoClaimsResult(claims.pop("sub"), claims)
