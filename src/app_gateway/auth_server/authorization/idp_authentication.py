from datetime import datetime, timedelta
from functools import partial
from typing import NamedTuple, assert_never

from fastapi import Response
from pydantic import BaseModel, ValidationError

from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
)
from app_gateway.common.tokens import hash_token
from app_gateway.common.validation import FormParams, parse_form_params_str
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
)
from app_gateway.oauth.responses import OauthRedirectResponse, OauthResponse
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    AppIdentityProvider,
    ClientType,
    IdentityProvider,
    User,
    decrypt_app_idp_client_secret,
)
from app_gateway.session import (
    AuthorizationScope,
    AuthorizationState,
    IdpAuthorizationState,
    IdpSession,
    Session,
    SessionGrant,
    encrypt_idp_refresh_token,
)
from app_gateway.session.schema import AuthorizationCodeSessionGrant, SessionGrantType


def _error_response(
    issuer: str,
    error: AuthorizationError,
) -> Response:
    return OauthResponse(
        AuthorizationErrorResponse(
            error=error,
            iss=issuer,
        ),
        status_code=400,
    )


def _error_redirect(
    issuer: str,
    redirect_uri: str,
    state: str | None,
    error: AuthorizationError,
) -> Response:
    return OauthRedirectResponse(
        redirect_uri,
        AuthorizationErrorResponse(
            error=error,
            state=state,
            iss=issuer,
        ),
    )


class AuthorizationRequestClient(BaseModel):
    client_id: str
    redirect_uri: str


def parse_authorization_request_client_id(params: FormParams) -> str | None:
    return parse_form_params_str(params, "client_id")


class ParseAuthorizationRequestResult(NamedTuple):
    request: AuthorizationRequest
    app_idp: AppIdentityProvider
    idp: IdentityProvider
    access_type: AccessType


class ClientAccessRequest(NamedTuple):
    resource_uri: str
    access_type: AccessType


def parse_authorization_request(
    maybe_client_app_idps: ClientAppIdentityProviders | None,
    params: FormParams,
    issuer: str,
) -> ParseAuthorizationRequestResult | Response:
    maybe_redirect_uri = parse_form_params_str(params, key="redirect_uri")

    match maybe_client_app_idps:
        case ClientAppIdentityProviders(client, app_idps) if (
            maybe_redirect_uri in client.redirect_uris
        ):
            error_response = partial(
                _error_redirect,
                issuer,
                maybe_redirect_uri,
                parse_form_params_str(params, "state"),
            )
        case ClientAppIdentityProviders() | None:
            return _error_response(issuer, AuthorizationError.UNAUTHORIZED_CLIENT)
        case unreachable:
            assert_never(unreachable)

    try:
        request = AuthorizationRequest.model_validate(params)
    except ValidationError as e:
        match e.errors():
            case [{"type": "enum", "loc": ("response_type",)}]:
                return error_response(AuthorizationError.UNSUPPORTED_RESPONSE_TYPE)
            case [{"type": "string_type", "loc": ("resource",)}]:
                return error_response(AuthorizationError.INVALID_TARGET)
            case list():
                return error_response(AuthorizationError.INVALID_REQUEST)
            case unreachable:
                assert_never(unreachable)

    match app_idps:
        case [AppIdpIdentityProvider(app_idp, idp)]:
            pass
        case []:
            return error_response(AuthorizationError.UNAUTHORIZED_CLIENT)
        case list():
            return error_response(AuthorizationError.SERVER_ERROR)
        case unreachable:
            assert_never(unreachable)

    access_type = (
        AccessType.PUBLIC
        if client.client_type is ClientType.PUBLIC
        else AccessType.AUTHENTICATED
    )

    return ParseAuthorizationRequestResult(request, app_idp, idp, access_type)


class CreateIdpAuthorizationRedirectResult(NamedTuple):
    state: IdpAuthorizationState
    response: OauthRedirectResponse[AuthorizationRequest]


def create_idp_authorization_redirect(
    request: AuthorizationRequest,
    app_idp: AppIdentityProvider,
    idp: IdentityProvider,
    maybe_access_rule: AppAccessRule | None,
    idp_state: str,
    idp_code_verifier: str,
    callback_url: str,
    time: datetime,
    issuer: str,
) -> CreateIdpAuthorizationRedirectResult | Response:
    if request.resource is not None and maybe_access_rule is None:
        return _error_redirect(
            issuer,
            request.redirect_uri,
            request.state,
            AuthorizationError.INVALID_TARGET,
        )

    return CreateIdpAuthorizationRedirectResult(
        IdpAuthorizationState(
            state_hash=hash_token(idp_state),
            client_id=request.client_id,
            request_scope=AuthorizationScope(
                resource=request.resource,
                scope=request.scope,
            ),
            request_state=AuthorizationState(
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                redirect_uri=request.redirect_uri,
                state=request.state,
                nonce=request.nonce,
            ),
            idp_slug=idp.slug,
            idp_issuer=idp.issuer,
            code_verifier=idp_code_verifier,
            issued_at=time,
        ),
        OauthRedirectResponse(
            idp.authorization_endpoint,
            AuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=app_idp.client_id,
                code_challenge=compute_code_challenge(idp_code_verifier),
                code_challenge_method=CodeChallengeMethod.S256,
                redirect_uri=str(callback_url),
                state=idp_state,
            ),
        ),
    )


def parse_authorization_callback_state_token(params: FormParams) -> str | None:
    return parse_form_params_str(params, "state")


class ParseAuthorizationCallbackResponseResult(NamedTuple):
    state: IdpAuthorizationState
    code: str


def parse_authorization_callback_response(
    maybe_state: IdpAuthorizationState | None,
    params: FormParams,
    time: datetime,
    issuer: str,
    state_lifetime: timedelta,
) -> ParseAuthorizationCallbackResponseResult | Response:
    if maybe_state is None or time - maybe_state.issued_at > state_lifetime:
        return _error_response(issuer, AuthorizationError.INVALID_REQUEST)

    maybe_iss = parse_form_params_str(params, "iss")
    if maybe_iss is not None and maybe_iss != maybe_state.idp_issuer:
        return _error_response(issuer, AuthorizationError.INVALID_REQUEST)

    error_response = partial(
        _error_redirect,
        issuer,
        maybe_state.request_state.redirect_uri,
        maybe_state.request_state.state,
    )

    code = parse_form_params_str(params, "code")
    if code is None:
        match parse_form_params_str(params, "error"):
            case AuthorizationError.ACCESS_DENIED:
                return error_response(AuthorizationError.ACCESS_DENIED)
            case AuthorizationError.TEMPORARILY_UNAVAILABLE:
                return error_response(AuthorizationError.TEMPORARILY_UNAVAILABLE)
            case str() | None:
                return error_response(AuthorizationError.SERVER_ERROR)
            case unreachable:
                assert_never(unreachable)

    return ParseAuthorizationCallbackResponseResult(maybe_state, code)


class AuthorizationCodeTokenRequestResult(NamedTuple):
    idp: IdentityProvider
    request: AuthorizationCodeTokenRequest


def create_idp_authorization_code_token_request(
    maybe_app_idp: AppIdpIdentityProvider | None,
    state: IdpAuthorizationState,
    code: str,
    callback_url: str,
    issuer: str,
    secret_enc_key: bytes,
) -> AuthorizationCodeTokenRequestResult | Response:
    match maybe_app_idp:
        case AppIdpIdentityProvider(app_idp, idp):
            pass
        case None:
            return _error_redirect(
                issuer,
                state.request_state.redirect_uri,
                state.request_state.state,
                AuthorizationError.SERVER_ERROR,
            )
        case unreachable:
            assert_never(unreachable)

    return AuthorizationCodeTokenRequestResult(
        idp,
        AuthorizationCodeTokenRequest(
            client_id=app_idp.client_id,
            client_secret=decrypt_app_idp_client_secret(secret_enc_key, app_idp),
            grant_type=GrantType.AUTHORIZATION_CODE,
            code=code,
            code_verifier=state.code_verifier,
            redirect_uri=callback_url,
        ),
    )


def create_idp_session(
    client_id: str,
    user_id: str,
    idp_issuer: str,
    token_response: TokenResponse,
    time: datetime,
    secret_enc_key: bytes,
    nonce: bytes,
    previous_refresh_token_enc: bytes | None = None,
) -> IdpSession:
    refresh_token_enc = (
        encrypt_idp_refresh_token(
            secret_enc_key,
            nonce,
            client_id,
            user_id,
            idp_issuer,
            token_response.refresh_token,
        )
        if token_response.refresh_token is not None
        else previous_refresh_token_enc
    )

    return IdpSession(
        client_id=client_id,
        user_id=user_id,
        idp_issuer=idp_issuer,
        expires_in=(
            timedelta(seconds=token_response.expires_in)
            if token_response.expires_in is not None
            else None
        ),
        refresh_token_enc=refresh_token_enc,
        issued_at=time,
    )


class CreateAuthorizationCodeResponseRedirectResult(NamedTuple):
    session: Session
    session_grant: SessionGrant
    response: OauthRedirectResponse[AuthorizationResponse]


def create_authorization_code_response_redirect(
    state: IdpAuthorizationState,
    user: User,
    session_id: str,
    authorization_code: str,
    issuer: str,
    time: datetime,
) -> CreateAuthorizationCodeResponseRedirectResult:
    return CreateAuthorizationCodeResponseRedirectResult(
        Session(
            session_id=session_id,
            client_id=state.client_id,
            user_id=user.user_id,
            idp_issuer=state.idp_issuer,
            scope=state.request_scope,
            issued_at=time,
        ),
        AuthorizationCodeSessionGrant(
            grant_type=SessionGrantType.AUTHORIZATION_CODE,
            token_hash=hash_token(authorization_code),
            session_id=session_id,
            state=state.request_state,
            issued_at=time,
        ),
        OauthRedirectResponse(
            state.request_state.redirect_uri,
            AuthorizationResponse(
                code=authorization_code,
                state=state.request_state.state,
                iss=issuer,
            ),
        ),
    )
