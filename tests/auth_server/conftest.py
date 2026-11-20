from datetime import timedelta
from types import SimpleNamespace

import pytest
from joserfc import jwk

from app_gateway.auth_server.policy_manager import (
    AppIdpIdentityProvider,
    ClientAppIdentityProviders,
    UserIdentity,
)
from app_gateway.common.jose import get_token_signing_key
from app_gateway.common.tokens import hash_token
from app_gateway.oauth import (
    CodeChallengeMethod,
    compute_code_challenge,
    generate_code_verifier,
)
from app_gateway.policy import (
    AccessType,
    AppAccessRule,
    AppIdentityProvider,
    ClientType,
    ConfidentialClient,
    IdentityProvider,
    PublicClient,
    User,
    encrypt_app_idp_client_secret,
)
from app_gateway.policy import UserIdentity as PolicyUserIdentity
from app_gateway.session import (
    AuthorizationScope,
    AuthorizationState,
    DeviceAuthorizationState,
    DeviceIdpAuthorizationState,
    IdpAuthorizationState,
    Session,
)
from app_gateway.session.schema import AuthorizationCodeSessionGrant, SessionGrantType
from tests.auth_server.constants import (
    APP_ID,
    CLIENT_ID,
    CLIENT_SECRET,
    CREATED_AT,
    DEVICE_CODE,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_ID,
    IDP_ISSUER,
    IDP_SUBJECT,
    KEY_ROTATION_SCHEDULE,
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
    TOKEN_SIGNING_SEED,
    USER_ID,
)

_timestamps = {"created_at": CREATED_AT, "updated_at": CREATED_AT}


@pytest.fixture
def idp() -> IdentityProvider:
    return IdentityProvider(
        idp_id=IDP_ID,
        issuer=IDP_ISSUER,
        slug="test-idp",
        name="Test IdP",
        authorization_endpoint=f"{IDP_ISSUER}/authorize",
        token_endpoint=f"{IDP_ISSUER}/token",
        userinfo_endpoint=f"{IDP_ISSUER}/userinfo",
        userinfo_claims_map={},
        **_timestamps,
    )


@pytest.fixture
def app_idp() -> AppIdentityProvider:
    return AppIdentityProvider(
        app_id=APP_ID,
        idp_id=IDP_ID,
        client_id=IDP_CLIENT_ID,
        client_secret_enc=encrypt_app_idp_client_secret(
            SECRET_ENC_KEY, NONCE_BYTES, APP_ID, IDP_ID, IDP_CLIENT_SECRET
        ),
        **_timestamps,
    )


@pytest.fixture
def confidential_client() -> ConfidentialClient:
    return ConfidentialClient(
        client_type=ClientType.CONFIDENTIAL,
        name="Test Client",
        app_id=APP_ID,
        client_id=CLIENT_ID,
        redirect_uris=[REDIRECT_URI],
        client_secret_hash=hash_token(CLIENT_SECRET),
        **_timestamps,
    )


@pytest.fixture
def public_client() -> PublicClient:
    return PublicClient(
        client_type=ClientType.PUBLIC,
        name="Test Public Client",
        app_id=APP_ID,
        client_id=PUBLIC_CLIENT_ID,
        redirect_uris=[REDIRECT_URI],
        **_timestamps,
    )


@pytest.fixture
def app_idp_idp(
    app_idp: AppIdentityProvider, idp: IdentityProvider
) -> AppIdpIdentityProvider:
    return AppIdpIdentityProvider(app_idp, idp)


@pytest.fixture
def client_app_idps(
    confidential_client: ConfidentialClient, app_idp_idp: AppIdpIdentityProvider
) -> ClientAppIdentityProviders:
    return ClientAppIdentityProviders(confidential_client, [app_idp_idp])


@pytest.fixture
def access_rule() -> AppAccessRule:
    return AppAccessRule(
        rule_id="rule_test",
        app_id=APP_ID,
        resource_id="res_test",
        access_type=AccessType.AUTHENTICATED,
        **_timestamps,
    )


@pytest.fixture
def user() -> User:
    return User(
        user_id=USER_ID,
        claims={
            "name": "Test User",
            "preferred_username": "testuser",
            "email": "user@example.test",
        },
        **_timestamps,
    )


@pytest.fixture
def identity(user: User, idp: IdentityProvider) -> UserIdentity:
    return UserIdentity(
        user,
        PolicyUserIdentity(
            user_id=USER_ID, idp_id=IDP_ID, idp_subject=IDP_SUBJECT, **_timestamps
        ),
        idp,
    )


@pytest.fixture
def code_verifier() -> str:
    return generate_code_verifier()


@pytest.fixture
def code_challenge(code_verifier: str) -> str:
    return compute_code_challenge(code_verifier)


@pytest.fixture
def authorize_params(code_challenge: str) -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "resource": RESOURCE,
        "scope": SCOPE,
        "state": REQUEST_STATE,
        "nonce": REQUEST_NONCE,
    }


@pytest.fixture
def request_scope() -> AuthorizationScope:
    return AuthorizationScope(resource=RESOURCE, scope=SCOPE)


@pytest.fixture
def request_state(code_challenge: str) -> AuthorizationState:
    return AuthorizationState(
        code_challenge=code_challenge,
        code_challenge_method=CodeChallengeMethod.S256,
        redirect_uri=REDIRECT_URI,
        state=REQUEST_STATE,
        nonce=REQUEST_NONCE,
    )


@pytest.fixture
def idp_code_verifier() -> str:
    return generate_code_verifier()


@pytest.fixture
def idp_authorization_state(
    request_scope: AuthorizationScope,
    request_state: AuthorizationState,
    idp_code_verifier: str,
) -> IdpAuthorizationState:
    return IdpAuthorizationState(
        state_hash=hash_token("idp-state"),
        client_id=CLIENT_ID,
        request_scope=request_scope,
        request_state=request_state,
        idp_slug="test-idp",
        idp_issuer=IDP_ISSUER,
        code_verifier=idp_code_verifier,
        issued_at=TIME,
    )


@pytest.fixture
def device_idp_authorization_state(
    request_scope: AuthorizationScope,
    idp_code_verifier: str,
) -> DeviceIdpAuthorizationState:
    return DeviceIdpAuthorizationState(
        state_hash=hash_token("idp-state"),
        client_id=CLIENT_ID,
        request_scope=request_scope,
        request_state=DeviceAuthorizationState(
            device_code_hash=hash_token(DEVICE_CODE)
        ),
        idp_slug="test-idp",
        idp_issuer=IDP_ISSUER,
        code_verifier=idp_code_verifier,
        issued_at=TIME,
    )


@pytest.fixture
def session(request_scope: AuthorizationScope) -> Session:
    return Session(
        session_id=SESSION_ID,
        client_id=CLIENT_ID,
        user_id=USER_ID,
        idp_issuer=IDP_ISSUER,
        scope=request_scope,
        issued_at=TIME,
    )


@pytest.fixture
def authorization_code() -> str:
    return "authorization-code"


@pytest.fixture
def authorization_code_grant(
    request_state: AuthorizationState, authorization_code: str
) -> AuthorizationCodeSessionGrant:
    return AuthorizationCodeSessionGrant(
        grant_type=SessionGrantType.AUTHORIZATION_CODE,
        token_hash=hash_token(authorization_code),
        session_id=SESSION_ID,
        state=request_state,
        issued_at=TIME,
    )


@pytest.fixture
def lifetime_settings() -> SimpleNamespace:
    return SimpleNamespace(
        confidential_client_session_lifetime=timedelta(days=30),
        confidential_client_refresh_token_lifetime=timedelta(days=7),
        public_client_session_lifetime=timedelta(hours=8),
        public_client_refresh_token_lifetime=timedelta(hours=8),
    )


@pytest.fixture
def signing_key() -> jwk.Key:
    return get_token_signing_key(TOKEN_SIGNING_SEED, TIME, KEY_ROTATION_SCHEDULE)
