"""End-to-end authorization code + refresh flow through the pure auth_server core.

Mirrors routes/authorize.py and routes/token.py, replacing each DB/IdP call by
passing the previous step's output straight through.
"""

import base64
import json
from collections.abc import Callable
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Literal, NamedTuple

import pytest
from fastapi import Response
from joserfc import jwk, jwt

from app_gateway.auth_server.authorization.common import (
    parse_idp_authorization_callback_response,
)
from app_gateway.auth_server.authorization.device_authorization import (
    CheckDeviceVerificationResult,
    CreateDeviceAuthorizationResult,
    ParseDeviceAuthorizationRequestResult,
    ParseDeviceCallbackResponseResult,
    check_device_verification,
    create_device_authorization,
    create_device_idp_authorization_redirect,
    create_device_idp_token_request,
    create_device_session,
    parse_device_authorization_request,
    parse_device_verification_user_code,
)
from app_gateway.auth_server.authorization.idp_authentication import (
    AuthorizationCodeTokenRequestResult,
    CreateIdpAuthorizationRedirectResult,
    ParseAuthorizationCallbackResponseResult,
    ParseAuthorizationRequestResult,
    create_authorization_code_response_redirect,
    create_idp_authorization_code_token_request,
    create_idp_authorization_redirect,
    create_idp_session,
    parse_authorization_callback_response,
    parse_authorization_request,
)
from app_gateway.auth_server.grants.authorization_code import (
    parse_authorization_code_grant,
)
from app_gateway.auth_server.grants.common import (
    AuthenticateClientResult,
    CreateTokenResponseResult,
    ParseTokenRequestResult,
    TokenGrantResult,
    TokenReplayResult,
    authenticate_client,
    create_token_response,
    parse_token_request,
)
from app_gateway.auth_server.grants.device_code import (
    check_device_authorization,
    parse_device_code_grant,
)
from app_gateway.auth_server.grants.refresh_token import (
    IdpRefreshTokenRequestResult,
    IdpSessionRefresh,
    IdpSessionValid,
    check_idp_session,
    check_refresh_token_grant,
    create_idp_refresh_token_request,
    parse_refresh_token_grant,
)
from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
    UserIdentity,
)
from app_gateway.auth_server.session_manager import (
    RedeemSessionGrantResult,
    RestoreSessionGrantResult,
)
from app_gateway.common.tokens import hash_token
from app_gateway.common.validation import parse_form_params
from app_gateway.oauth import (
    AuthorizationCodeTokenRequest,
    DeviceCodeTokenRequest,
    GrantType,
    RefreshTokenTokenRequest,
    TokenResponse,
    compute_code_challenge,
)
from app_gateway.policy import AppAccessRule, PublicClient, User
from app_gateway.session import IdpSession, Session, decrypt_idp_refresh_token
from app_gateway.session.schema import AuthorizationCodeSessionGrant
from tests.auth_server.constants import (
    CALLBACK_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_ISSUER,
    ISSUER,
    NONCE_BYTES,
    PUBLIC_CLIENT_ID,
    REDIRECT_URI,
    REQUEST_NONCE,
    REQUEST_STATE,
    RESOURCE,
    SCOPE,
    SECRET_ENC_KEY,
    SESSION_ID,
    TIME,
    USER_ID,
)
from tests.auth_server.helpers import redirect_location

type ClientAuth = Literal["client_secret_post", "client_secret_basic", "none"]

_IDP_TOKEN_RESPONSE = TokenResponse(access_token="idp-at", token_type="Bearer")


def _token_auth(
    client_id: str, client_auth: ClientAuth
) -> tuple[dict[str, str], str | None]:
    """Token request params and Authorization header for a client auth method."""
    match client_auth:
        case "client_secret_post":
            return {"client_id": client_id, "client_secret": CLIENT_SECRET}, None
        case "client_secret_basic":
            encoded = base64.b64encode(f"{client_id}:{CLIENT_SECRET}".encode())
            return {}, f"Basic {encoded.decode()}"
        case "none":
            return {"client_id": client_id}, None


class _IssuedTokens(NamedTuple):
    session: Session
    idp_session: IdpSession
    authenticated: AuthenticateClientResult
    tokens: CreateTokenResponseResult
    body: dict[str, Any]


def _authorization_code_flow(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    access_rule: AppAccessRule,
    user: User,
    identity: UserIdentity,
    authorize_params: dict[str, str],
    code_verifier: str,
    idp_code_verifier: str,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
    client_auth: ClientAuth = "client_secret_post",
    idp_token_response: TokenResponse = _IDP_TOKEN_RESPONSE,
) -> _IssuedTokens:
    """Run authorize -> IdP callback -> code exchange, returning what was issued."""
    client_id = client_app_idps.client.client_id
    authorize_params = authorize_params | {"client_id": client_id}

    # GET /oauth/authorize
    parsed = parse_authorization_request(
        client_app_idps, parse_form_params(list(authorize_params.items())), ISSUER
    )
    assert isinstance(parsed, ParseAuthorizationRequestResult)

    redirect = create_idp_authorization_redirect(
        parsed.request,
        parsed.app_idp,
        parsed.idp,
        access_rule,
        "idp-state",
        idp_code_verifier,
        CALLBACK_URL,
        TIME,
        ISSUER,
    )
    assert isinstance(redirect, CreateIdpAuthorizationRedirectResult)
    _, idp_request = redirect_location(redirect.response)

    # IdP authenticates the user and redirects to /oauth/broker/{idp}/callback
    callback = parse_authorization_callback_response(
        redirect.state,
        {"code": "idp-code", "state": idp_request["state"], "iss": IDP_ISSUER},
        TIME + timedelta(seconds=30),
        ISSUER,
        timedelta(minutes=5),
    )
    assert isinstance(callback, ParseAuthorizationCallbackResponseResult)

    idp_token_request = create_idp_authorization_code_token_request(
        app_idp_idp,
        callback.state,
        callback.code,
        idp_request["redirect_uri"],
        ISSUER,
        SECRET_ENC_KEY,
    )
    assert isinstance(idp_token_request, AuthorizationCodeTokenRequestResult)
    assert idp_token_request.request.client_secret == IDP_CLIENT_SECRET
    # The IdP would verify our PKCE challenge against this verifier.
    assert (
        compute_code_challenge(idp_token_request.request.code_verifier)
        == idp_request["code_challenge"]
    )

    idp_session = create_idp_session(
        callback.state.client_id,
        user.user_id,
        callback.state.idp_issuer,
        idp_token_response,
        TIME,
        SECRET_ENC_KEY,
        NONCE_BYTES,
    )
    assert idp_session.user_id == USER_ID

    session, session_grant, client_redirect = (
        create_authorization_code_response_redirect(
            callback.state, user, SESSION_ID, "client-code", ISSUER, TIME
        )
    )
    location, client_params = redirect_location(client_redirect)
    assert location == REDIRECT_URI
    assert client_params["state"] == REQUEST_STATE
    assert client_params["iss"] == ISSUER

    # POST /oauth/token
    auth_params, authorization = _token_auth(client_id, client_auth)
    token_request = parse_token_request(
        {
            "grant_type": "authorization_code",
            "code": client_params["code"],
            "code_verifier": code_verifier,
            "redirect_uri": REDIRECT_URI,
        }
        | auth_params,
        authorization,
    )
    assert isinstance(token_request, ParseTokenRequestResult)
    assert isinstance(token_request.request, AuthorizationCodeTokenRequest)

    authenticated = authenticate_client(
        client_app_idps.client, token_request.credentials, lifetime_settings
    )
    assert isinstance(authenticated, AuthenticateClientResult)

    assert isinstance(session_grant, AuthorizationCodeSessionGrant)
    grant = parse_authorization_code_grant(
        RedeemSessionGrantResult(session_grant, session, replayed=False),
        authenticated.client,
        token_request.request,
        TIME + timedelta(minutes=1),
        authenticated.session_lifetime,
        timedelta(minutes=5),
    )
    assert isinstance(grant, TokenGrantResult)

    tokens = create_token_response(
        grant.session,
        authenticated.client,
        grant.request_scope,
        access_rule,
        identity,
        grant.nonce,
        signing_key,
        "jti-123",
        "refresh-token",
        ISSUER,
        TIME + timedelta(minutes=1),
        timedelta(hours=1),
        timedelta(hours=1),
    )
    assert isinstance(tokens, CreateTokenResponseResult)

    return _IssuedTokens(
        session,
        idp_session,
        authenticated,
        tokens,
        json.loads(bytes(tokens.response.body)),
    )


def test_authorization_code_flow(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    access_rule: AppAccessRule,
    user: User,
    identity: UserIdentity,
    authorize_params: dict[str, str],
    code_verifier: str,
    idp_code_verifier: str,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
) -> None:
    issued = _authorization_code_flow(
        client_app_idps,
        app_idp_idp,
        access_rule,
        user,
        identity,
        authorize_params,
        code_verifier,
        idp_code_verifier,
        lifetime_settings,
        signing_key,
    )
    body = issued.body
    assert body["scope"] == SCOPE

    access_claims = jwt.decode(body["access_token"], signing_key).claims
    assert access_claims["sub"] == USER_ID
    assert access_claims["aud"] == RESOURCE
    assert access_claims["client_id"] == CLIENT_ID

    id_claims = jwt.decode(body["id_token"], signing_key).claims
    assert id_claims["sub"] == USER_ID
    assert id_claims["aud"] == CLIENT_ID
    assert id_claims["nonce"] == REQUEST_NONCE


def test_refresh_token_flow(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    access_rule: AppAccessRule,
    user: User,
    identity: UserIdentity,
    authorize_params: dict[str, str],
    code_verifier: str,
    idp_code_verifier: str,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
) -> None:
    issued = _authorization_code_flow(
        client_app_idps,
        app_idp_idp,
        access_rule,
        user,
        identity,
        authorize_params,
        code_verifier,
        idp_code_verifier,
        lifetime_settings,
        signing_key,
    )
    session, idp_session, authenticated, tokens, body = issued
    id_claims = jwt.decode(body["id_token"], signing_key).claims

    # POST /oauth/token (grant_type=refresh_token), using the token just issued
    refresh_time = TIME + timedelta(hours=2)
    refresh_grant = tokens.refresh_token_grant
    # The session store looks the grant up by this hash.
    assert refresh_grant.token_hash == hash_token(body["refresh_token"])

    refresh_request = parse_token_request(
        {
            "grant_type": "refresh_token",
            "refresh_token": body["refresh_token"],
            "scope": "openid email",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        None,
    )
    assert isinstance(refresh_request, ParseTokenRequestResult)
    assert isinstance(refresh_request.request, RefreshTokenTokenRequest)

    restored = RestoreSessionGrantResult(refresh_grant, session, idp_session)
    checked = check_refresh_token_grant(
        restored,
        authenticated.client,
        refresh_time,
        authenticated.session_lifetime,
        authenticated.refresh_token_lifetime,
    )
    assert checked is restored
    # The IdP gave no expires_in, so its session never needs refreshing.
    assert check_idp_session(idp_session, session, refresh_time) == IdpSessionValid()

    refreshed = parse_refresh_token_grant(
        RedeemSessionGrantResult(refresh_grant, session, replayed=False),
        authenticated.client,
        refresh_request.request,
        refresh_time,
        authenticated.session_lifetime,
        authenticated.refresh_token_lifetime,
    )
    assert isinstance(refreshed, TokenGrantResult)

    refreshed_tokens = create_token_response(
        refreshed.session,
        authenticated.client,
        refreshed.request_scope,
        access_rule,
        identity,
        refreshed.nonce,
        signing_key,
        "jti-456",
        "refresh-token-2",
        ISSUER,
        refresh_time,
        timedelta(hours=1),
        timedelta(hours=1),
    )
    assert isinstance(refreshed_tokens, CreateTokenResponseResult)

    refreshed_body = json.loads(bytes(refreshed_tokens.response.body))
    assert refreshed_body["scope"] == "openid email"
    assert refreshed_body["refresh_token"] != body["refresh_token"]
    assert refreshed_tokens.refresh_token_grant.session_id == SESSION_ID

    refreshed_access = jwt.decode(refreshed_body["access_token"], signing_key).claims
    assert refreshed_access["sub"] == USER_ID
    assert refreshed_access["aud"] == RESOURCE
    assert refreshed_access["scope"] == "openid email"

    refreshed_id = jwt.decode(refreshed_body["id_token"], signing_key).claims
    assert refreshed_id["sub"] == USER_ID
    assert refreshed_id["auth_time"] == id_claims["auth_time"]
    assert "nonce" not in refreshed_id


type RunFlow = Callable[..., _IssuedTokens]


@pytest.fixture
def run_flow(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    access_rule: AppAccessRule,
    user: User,
    identity: UserIdentity,
    authorize_params: dict[str, str],
    code_verifier: str,
    idp_code_verifier: str,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
) -> RunFlow:
    """_authorization_code_flow with the standard fixtures bound."""

    default_client_app_idps = client_app_idps

    def run(
        *,
        client_app_idps: ClientAppIdentityProviders = default_client_app_idps,
        client_auth: ClientAuth = "client_secret_post",
        idp_token_response: TokenResponse = _IDP_TOKEN_RESPONSE,
    ) -> _IssuedTokens:
        return _authorization_code_flow(
            client_app_idps,
            app_idp_idp,
            access_rule,
            user,
            identity,
            authorize_params,
            code_verifier,
            idp_code_verifier,
            lifetime_settings,
            signing_key,
            client_auth,
            idp_token_response,
        )

    return run


def test_authorization_code_flow_client_secret_basic(
    run_flow: RunFlow, signing_key: jwk.Key
) -> None:
    issued = run_flow(client_auth="client_secret_basic")

    assert issued.authenticated.client.client_id == CLIENT_ID
    claims = jwt.decode(issued.body["access_token"], signing_key).claims
    assert claims["client_id"] == CLIENT_ID


def test_authorization_code_flow_public_client(
    run_flow: RunFlow,
    public_client: PublicClient,
    app_idp_idp: AppIdpIdentityProvider,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
) -> None:
    issued = run_flow(
        client_app_idps=ClientAppIdentityProviders(public_client, [app_idp_idp]),
        client_auth="none",
    )

    assert issued.session.client_id == PUBLIC_CLIENT_ID
    assert issued.authenticated.session_lifetime == (
        lifetime_settings.public_client_session_lifetime
    )
    access_claims = jwt.decode(issued.body["access_token"], signing_key).claims
    assert access_claims["client_id"] == PUBLIC_CLIENT_ID
    id_claims = jwt.decode(issued.body["id_token"], signing_key).claims
    assert id_claims["aud"] == PUBLIC_CLIENT_ID


def test_refresh_token_flow_refreshes_idp_session(
    run_flow: RunFlow,
    app_idp_idp: AppIdpIdentityProvider,
) -> None:
    issued = run_flow(
        idp_token_response=TokenResponse(
            access_token="idp-at",
            token_type="Bearer",
            expires_in=300,
            refresh_token="idp-rt",
        )
    )
    session, idp_session = issued.session, issued.idp_session
    refresh_time = TIME + timedelta(hours=2)

    # The IdP access token has expired, so the IdP session must be refreshed.
    match check_idp_session(idp_session, session, refresh_time):
        case IdpSessionRefresh(to_refresh):
            assert to_refresh is idp_session
        case other:
            raise AssertionError(other)

    idp_refresh = create_idp_refresh_token_request(
        app_idp_idp, idp_session, session, SECRET_ENC_KEY
    )
    assert isinstance(idp_refresh, IdpRefreshTokenRequestResult)
    assert idp_refresh.request.client_id == IDP_CLIENT_ID
    assert idp_refresh.request.client_secret == IDP_CLIENT_SECRET
    assert idp_refresh.request.refresh_token == "idp-rt"

    # The IdP doesn't rotate its refresh token, so the previous one is kept.
    refreshed_idp_session = create_idp_session(
        idp_session.client_id,
        idp_session.user_id,
        idp_session.idp_issuer,
        TokenResponse(access_token="idp-at-2", token_type="Bearer", expires_in=300),
        refresh_time,
        SECRET_ENC_KEY,
        NONCE_BYTES,
        previous_refresh_token_enc=idp_session.refresh_token_enc,
    )
    assert (
        check_idp_session(refreshed_idp_session, session, refresh_time)
        == IdpSessionValid()
    )
    assert decrypt_idp_refresh_token(SECRET_ENC_KEY, refreshed_idp_session) == "idp-rt"


def test_refresh_token_flow_detects_rotated_token_reuse(run_flow: RunFlow) -> None:
    issued = run_flow()
    session, idp_session, authenticated, tokens, _ = issued
    refresh_time = TIME + timedelta(hours=2)
    old_grant = tokens.refresh_token_grant

    # After a successful refresh, the store invalidates the redeemed grant.
    used_grant = old_grant.model_copy(update={"invalidated_at": refresh_time})
    reuse_time = refresh_time + timedelta(minutes=5)

    checked = check_refresh_token_grant(
        RestoreSessionGrantResult(used_grant, session, idp_session),
        authenticated.client,
        reuse_time,
        authenticated.session_lifetime,
        authenticated.refresh_token_lifetime,
    )
    assert isinstance(checked, TokenReplayResult)
    assert checked.session_id == SESSION_ID

    redeemed = parse_refresh_token_grant(
        RedeemSessionGrantResult(used_grant, session, replayed=True),
        authenticated.client,
        RefreshTokenTokenRequest(
            grant_type=GrantType.REFRESH_TOKEN,
            refresh_token=issued.body["refresh_token"],
        ),
        reuse_time,
        authenticated.session_lifetime,
        authenticated.refresh_token_lifetime,
    )
    assert isinstance(redeemed, TokenReplayResult)
    assert redeemed.session_id == SESSION_ID


def test_device_authorization_flow(
    client_app_idps: ClientAppIdentityProviders,
    app_idp_idp: AppIdpIdentityProvider,
    access_rule: AppAccessRule,
    user: User,
    identity: UserIdentity,
    idp_code_verifier: str,
    lifetime_settings: SimpleNamespace,
    signing_key: jwk.Key,
) -> None:
    device_code_lifetime = timedelta(minutes=10)
    client = client_app_idps.client
    client_params = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}

    # POST /oauth/device_authorization
    parsed = parse_device_authorization_request(
        client_params | {"resource": RESOURCE, "scope": SCOPE}, None
    )
    assert isinstance(parsed, ParseDeviceAuthorizationRequestResult)
    authenticated = authenticate_client(client, parsed.credentials, lifetime_settings)
    assert isinstance(authenticated, AuthenticateClientResult)

    created = create_device_authorization(
        authenticated.client.client_id,
        parsed.request,
        access_rule,
        "device-code",
        "BCDF-GHJK",
        f"{ISSUER}/oauth/device",
        TIME,
        device_code_lifetime,
        timedelta(seconds=5),
    )
    assert isinstance(created, CreateDeviceAuthorizationResult)
    device_auth = created.device_auth
    device_response = json.loads(bytes(created.response.body))

    # The device polls POST /oauth/token before the user has approved.
    token_request = parse_token_request(
        client_params
        | {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_response["device_code"],
        },
        None,
    )
    assert isinstance(token_request, ParseTokenRequestResult)
    assert isinstance(token_request.request, DeviceCodeTokenRequest)
    pending = check_device_authorization(
        device_auth, client, TIME + timedelta(seconds=5), device_code_lifetime
    )
    assert isinstance(pending, Response)
    assert json.loads(bytes(pending.body)) == {"error": "authorization_pending"}

    # The user enters the code at POST /oauth/device, with different formatting.
    user_code = parse_device_verification_user_code({"user_code": "bcdf ghjk"})
    assert user_code is not None
    assert hash_token(user_code) == device_auth.user_code_hash
    verified = check_device_verification(
        device_auth, client_app_idps, TIME + timedelta(minutes=1), device_code_lifetime
    )
    assert isinstance(verified, CheckDeviceVerificationResult)

    redirect = create_device_idp_authorization_redirect(
        verified.device_auth,
        verified.app_idp,
        verified.idp,
        "idp-state",
        idp_code_verifier,
        CALLBACK_URL,
        TIME + timedelta(minutes=1),
    )
    _, idp_request = redirect_location(redirect.response)

    # IdP authenticates the user and redirects to /oauth/broker/{idp}/callback
    callback = parse_idp_authorization_callback_response(
        redirect.state,
        {"code": "idp-code", "state": idp_request["state"], "iss": IDP_ISSUER},
        TIME + timedelta(minutes=2),
        ISSUER,
        timedelta(minutes=5),
    )
    assert callback == ParseDeviceCallbackResponseResult(redirect.state, "idp-code")

    idp_token_request = create_device_idp_token_request(
        app_idp_idp,
        callback.state,
        callback.code,
        idp_request["redirect_uri"],
        SECRET_ENC_KEY,
    )
    assert isinstance(idp_token_request, AuthorizationCodeTokenRequestResult)
    assert idp_token_request.request.client_secret == IDP_CLIENT_SECRET
    assert (
        compute_code_challenge(idp_token_request.request.code_verifier)
        == idp_request["code_challenge"]
    )

    session, session_grant = create_device_session(
        callback.state, user, SESSION_ID, TIME + timedelta(minutes=2)
    )
    # The store marks the device authorization approved alongside the session.
    approved = device_auth.model_copy(update={"approved_at": session.issued_at})

    # The device polls again and receives tokens.
    poll_time = TIME + timedelta(minutes=3)
    assert (
        check_device_authorization(approved, client, poll_time, device_code_lifetime)
        is None
    )
    grant = parse_device_code_grant(
        RedeemSessionGrantResult(session_grant, session, replayed=False),
        authenticated.client,
        token_request.request,
        poll_time,
        authenticated.session_lifetime,
    )
    assert isinstance(grant, TokenGrantResult)

    tokens = create_token_response(
        grant.session,
        authenticated.client,
        grant.request_scope,
        access_rule,
        identity,
        grant.nonce,
        signing_key,
        "jti-123",
        "refresh-token",
        ISSUER,
        poll_time,
        timedelta(hours=1),
        timedelta(hours=1),
    )
    assert isinstance(tokens, CreateTokenResponseResult)
    body = json.loads(bytes(tokens.response.body))
    assert body["scope"] == SCOPE
    assert body["refresh_token"] == "refresh-token"
    access_claims = jwt.decode(body["access_token"], signing_key).claims
    assert access_claims["sub"] == USER_ID
    assert access_claims["aud"] == RESOURCE
    id_claims = jwt.decode(body["id_token"], signing_key).claims
    assert id_claims["sub"] == USER_ID
    assert "nonce" not in id_claims

    # Redeeming the device code a second time is a replay.
    replayed = parse_device_code_grant(
        RedeemSessionGrantResult(session_grant, session, replayed=True),
        authenticated.client,
        token_request.request,
        poll_time,
        authenticated.session_lifetime,
    )
    assert isinstance(replayed, TokenReplayResult)
    assert replayed.session_id == SESSION_ID
