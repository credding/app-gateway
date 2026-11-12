import json
from typing import Annotated, Any

import httpx2
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import IntegrityError

from app_gateway.authorization_server.policy_manager import (
    lookup_app_access_rule,
    lookup_client_app_idps,
    lookup_user,
    register_user,
    update_user_claims,
)
from app_gateway.authorization_server.session_manager import (
    invalidate_idp_authorization_state,
    restore_idp_authorization_state,
    save_authorization_code_state,
    save_idp_authorization_state,
    save_idp_session,
)
from app_gateway.common.clock import now
from app_gateway.common.http import get_http_client
from app_gateway.common.tokens import hash_token
from app_gateway.common.validation import validate_params
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    AuthorizationError,
    AuthorizationErrorResponse,
    AuthorizationRequest,
    AuthorizationResponse,
    CodeChallengeMethod,
    GrantType,
    ResponseType,
    TokenResponse,
    compute_code_challenge,
    generate_authorization_code,
    generate_code_verifier,
    generate_state_token,
)
from app_gateway.oauth.responses import OauthJsonResponse, OauthRedirectResponse
from app_gateway.policy import (
    AccessType,
    ClientType,
    decrypt_app_idp_client_secret,
    generate_user_id,
)
from app_gateway.session import (
    AuthorizationCodeState,
    AuthorizationRequestClientState,
    AuthorizationRequestScope,
    IdpAuthorizationState,
    IdpSession,
    encrypt_idp_refresh_token,
)
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
) -> Response:
    issuer = settings.auth_server_issuer
    params = api_request.query_params.multi_items()

    try:
        request_client = validate_params(AuthorizationRequestClient, params)
    except ValidationError:
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    client_app_idps = await lookup_client_app_idps(request_client.client_id)
    if client_app_idps is None:
        return _error_response(AuthorizationError.UNAUTHORIZED_CLIENT, issuer)

    client, app_idps = client_app_idps
    if request_client.redirect_uri not in client.redirect_uris:
        return _error_response(AuthorizationError.UNAUTHORIZED_CLIENT, issuer)

    redirect_uri = request_client.redirect_uri

    try:
        request_state = validate_params(AuthorizationRequestState, params)
    except ValidationError:
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
            AccessType.PUBLIC
            if client.client_type is ClientType.PUBLIC
            else AccessType.AUTHENTICATED
        )
        access_rule = await lookup_app_access_rule(
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

    await save_idp_authorization_state(
        IdpAuthorizationState(
            state_hash=hash_token(idp_state),
            client_id=client.client_id,
            request_scope=AuthorizationRequestScope(
                resource=request.resource,
                scope=request.scope,
            ),
            request_state=AuthorizationRequestClientState(
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

    callback_url = api_request.url_for("oauth_broker_callback", idp_slug=idp.slug)

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


class BrokerCallbackState(BaseModel):
    state: str


class BrokerCallbackIssuer(BaseModel):
    iss: str | None = None


class BrokerCallbackCode(BaseModel):
    code: str


class BrokerCallbackError(BaseModel):
    error: AuthorizationError


@router.get("/oauth/broker/{idp_slug}/callback")
async def oauth_broker_callback(  # ruff: ignore[too-many-return-statements, too-many-statements]
    api_request: Request,
    idp_slug: str,
    settings: Annotated[Settings, Depends(get_settings)],
    http_client: Annotated[httpx2.AsyncClient, Depends(get_http_client)],
) -> Response:
    issuer = settings.auth_server_issuer
    params = api_request.query_params.multi_items()
    time = now()

    try:
        callback_state = validate_params(BrokerCallbackState, params)
    except ValidationError:
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    state_hash = hash_token(callback_state.state)
    idp_state = await restore_idp_authorization_state(state_hash)
    if idp_state is None:
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    # Consume the state before doing anything else so it can only be used once.
    if not await invalidate_idp_authorization_state(state_hash):
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    if time - idp_state.issued_at > settings.idp_authorization_state_lifetime:
        return _error_response(AuthorizationError.INVALID_REQUEST, issuer)

    request_state = idp_state.request_state

    def error_redirect(error: AuthorizationError) -> Response:
        return _error_redirect(
            request_state.redirect_uri,
            error,
            request_state.state,
            issuer,
        )

    client_app_idps = await lookup_client_app_idps(idp_state.client_id)
    if client_app_idps is None:
        return error_redirect(AuthorizationError.SERVER_ERROR)

    _, app_idps = client_app_idps

    app_idp = next(
        (
            (app_idp, idp)
            for app_idp, idp in app_idps
            if idp.issuer == idp_state.idp_issuer
        ),
        None,
    )
    if app_idp is None:
        return error_redirect(AuthorizationError.SERVER_ERROR)

    app_idp, idp = app_idp

    if idp_slug != idp.slug:
        return error_redirect(AuthorizationError.SERVER_ERROR)

    try:
        callback_issuer = validate_params(BrokerCallbackIssuer, params)
    except ValidationError:
        return error_redirect(AuthorizationError.SERVER_ERROR)

    if callback_issuer.iss is not None and callback_issuer.iss != idp.issuer:
        return error_redirect(AuthorizationError.SERVER_ERROR)

    try:
        callback_code = validate_params(BrokerCallbackCode, params)
    except ValidationError:
        try:
            callback_error = validate_params(BrokerCallbackError, params)
            match callback_error.error:
                case (
                    AuthorizationError.ACCESS_DENIED
                    | AuthorizationError.TEMPORARILY_UNAVAILABLE
                ):
                    return error_redirect(callback_error.error)
                case _:
                    return error_redirect(AuthorizationError.SERVER_ERROR)
        except ValidationError:
            return error_redirect(AuthorizationError.SERVER_ERROR)

    encryption_key = settings.secret_encryption_key.get_secret_value()
    callback_url = api_request.url_for("oauth_broker_callback", idp_slug=idp_slug)

    try:
        idp_token_response = await http_client.post(
            idp.token_endpoint,
            data=AuthorizationCodeTokenRequest(
                client_id=app_idp.client_id,
                client_secret=decrypt_app_idp_client_secret(encryption_key, app_idp),
                grant_type=GrantType.AUTHORIZATION_CODE,
                code=callback_code.code,
                code_verifier=idp_state.idp_code_verifier,
                redirect_uri=str(callback_url),
            ).model_dump(mode="json", exclude_none=True),
        )
        idp_token_response.raise_for_status()
        idp_token = TokenResponse.model_validate_json(idp_token_response.content)

        userinfo_response = await http_client.get(
            idp.userinfo_endpoint,
            headers={"authorization": f"Bearer {idp_token.access_token}"},
        )
        userinfo_response.raise_for_status()

        userinfo_claims: dict[str, Any] = json.loads(userinfo_response.content)

        claims = {k: userinfo_claims[v] for k, v in idp.userinfo_claims_map.items()}
        idp_subject = claims.pop("sub")

    except (
        httpx2.HTTPError,  # error response from upstream
        ValidationError,  # bad token response
        InvalidTag,  # key decryption failed
        json.JSONDecodeError,  # bad userinfo response
        TypeError,  # bad userinfo response
        KeyError,  # bad userinfo mapping
    ):
        return error_redirect(AuthorizationError.SERVER_ERROR)

    user = await lookup_user(idp_state.idp_issuer, idp_subject)
    if user is None:
        try:
            user = await register_user(
                idp_state.idp_issuer,
                idp_subject,
                generate_user_id(),
                claims,
                time,
            )
        except IntegrityError:
            user = await lookup_user(idp_state.idp_issuer, idp_subject)
            if user is None:
                return error_redirect(AuthorizationError.SERVER_ERROR)
    elif user.claims != claims:
        user = await update_user_claims(user, claims, time)

    if idp_token.refresh_token:
        await save_idp_session(
            IdpSession(
                client_id=idp_state.client_id,
                user_id=user.user_id,
                idp_issuer=idp.issuer,
                expires_in=idp_token.expires_in,
                refresh_token_enc=encrypt_idp_refresh_token(
                    encryption_key,
                    idp_state.client_id,
                    user.user_id,
                    idp.issuer,
                    idp_token.refresh_token,
                ),
                issued_at=time,
            )
        )

    code = generate_authorization_code()
    await save_authorization_code_state(
        AuthorizationCodeState(
            code_hash=hash_token(code),
            client_id=idp_state.client_id,
            user_id=user.user_id,
            request_scope=idp_state.request_scope,
            request_state=request_state,
            idp_issuer=idp.issuer,
            issued_at=time,
        )
    )

    return OauthRedirectResponse(
        request_state.redirect_uri,
        AuthorizationResponse(code=code, state=request_state.state, iss=issuer),
    )


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
