from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ValidationError

from app_gateway import policy_schema as policy
from app_gateway import session_schema as schema
from app_gateway.authorization_server.policy_manager import (
    PolicyManager,
    get_policy_manager,
)
from app_gateway.authorization_server.session_manager import (
    SessionManager,
    get_session_manager,
)
from app_gateway.common.clock import now
from app_gateway.common.tokens import hash_token
from app_gateway.common.validation import validate_params
from app_gateway.oauth import (
    AuthorizationError,
    AuthorizationErrorResponse,
    AuthorizationRequest,
    CodeChallengeMethod,
    ResponseType,
    compute_code_challenge,
    generate_code_verifier,
    generate_state_token,
)
from app_gateway.oauth.responses import OauthJsonResponse, OauthRedirectResponse
from app_gateway.policy_schema import ClientType
from app_gateway.settings import Settings, get_settings

router = APIRouter()


class AuthorizationRequestClient(BaseModel):
    client_id: str
    redirect_uri: str


class AuthorizationRequestState(BaseModel):
    state: str


@router.get("/oauth/authorize")
async def oauth_authorize(  # ruff: ignore[too-many-return-statements]
    api_request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    policy_manager: Annotated[PolicyManager, Depends(get_policy_manager)],
    session_manager: Annotated[SessionManager, Depends(get_session_manager)],
) -> Response:
    issuer = settings.auth_server_issuer
    params = api_request.query_params.multi_items()

    try:
        request_client = validate_params(AuthorizationRequestClient, params)
    except ValidationError as e:
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    client_app_idps = await policy_manager.get_client_app_idps(request_client.client_id)
    if client_app_idps is None:
        return _error_response(AuthorizationError.UNAUTHORIZED_CLIENT, issuer)

    client, app_idps = client_app_idps
    if request_client.redirect_uri not in client.redirect_uris:
        return _error_response(AuthorizationError.UNAUTHORIZED_CLIENT, issuer)

    redirect_uri = request_client.redirect_uri

    try:
        request_state = validate_params(AuthorizationRequestState, params)
    except ValidationError as e:
        return _error_redirect(
            redirect_uri, AuthorizationError.INVALID_REQUEST, None, issuer
        )

    state = request_state.state

    try:
        request = validate_params(AuthorizationRequest, params)
    except ValidationError as e:
        if _is_unsupported_response_type(e):
            return _error_redirect(
                redirect_uri,
                AuthorizationError.UNSUPPORTED_RESPONSE_TYPE,
                state,
                issuer,
            )
        return _error_redirect(
            redirect_uri,
            AuthorizationError.INVALID_REQUEST,
            state,
            issuer,
        )

    if request.resource is not None:
        access_type = (
            policy.AccessType.PUBLIC
            if client.client_type is ClientType.PUBLIC
            else policy.AccessType.AUTHENTICATED
        )
        access_rule = await policy_manager.get_client_app_access_rule(
            client.client_id, request.resource, access_type
        )
        if access_rule is None:
            return _error_redirect(
                redirect_uri,
                AuthorizationError.INVALID_TARGET,
                state,
                issuer,
            )

    if len(app_idps) == 0:
        return _error_redirect(
            redirect_uri,
            AuthorizationError.UNAUTHORIZED_CLIENT,
            state,
            issuer,
        )
    if len(app_idps) > 1:
        return _error_redirect(
            redirect_uri,
            AuthorizationError.SERVER_ERROR,
            state,
            issuer,
        )

    app_idp, idp = app_idps[0]

    idp_state = generate_state_token()
    idp_code_verifier = generate_code_verifier()

    await session_manager.save_idp_authorization_state(
        schema.IdpAuthorizationState(
            state_hash=hash_token(idp_state),
            client_id=client.client_id,
            request_scope=schema.AuthorizationRequestScope(
                resource=request.resource,
                scope=request.scope,
            ),
            request_state=schema.AuthorizationRequestState(
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                redirect_uri=redirect_uri,
                state=request.state,
            ),
            idp_issuer=idp.issuer,
            idp_code_verifier=idp_code_verifier,
            issued_at=now(),
        )
    )

    callback_url = api_request.url_for("oauth_broker_callback", idp_alias=idp.alias)

    return OauthRedirectResponse(
        idp.authorization_endpoint,
        AuthorizationRequest(
            response_type=ResponseType.CODE,
            client_id=app_idp.client_id,
            code_challenge=compute_code_challenge(idp_code_verifier),
            code_challenge_method=CodeChallengeMethod.S256,
            redirect_uri=str(callback_url),
            state=idp_state,
        ),
    )


@router.get("/oauth/broker/{idp_alias}/callback")
async def oauth_broker_callback() -> Response:
    pass


def _error_response(
    error: AuthorizationError,
    issuer: str,
) -> Response:
    return OauthJsonResponse(
        AuthorizationErrorResponse(
            error=error,
            iss=issuer,
        ),
        status_code=400,
    )


def _error_redirect(
    redirect_uri: str,
    error: AuthorizationError,
    state: str | None,
    issuer: str,
) -> Response:
    return OauthRedirectResponse(
        redirect_uri,
        AuthorizationErrorResponse(
            error=error,
            state=state,
            iss=issuer,
        ),
    )


def _is_unsupported_response_type(e: ValidationError) -> bool:
    return all(
        err["loc"] == ("response_type",) and err["type"] == "enum" for err in e.errors()
    )
