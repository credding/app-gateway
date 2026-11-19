"""RFC 8693 OAuth 2.0 Token Exchange.

Delegation semantics with the authenticated client as the implicit actor: the
issued token keeps the subject's `sub` and `sid`, and records the requester in
an `act` claim unless the requester is already the subject token's client.
"""

from datetime import datetime, timedelta
from typing import Any, NamedTuple

from fastapi import Response
from joserfc import jwk, jwt
from joserfc.errors import JoseError

from app_gateway.auth_server.grants.common import (
    client_access_type,
    create_access_token,
    token_error_response,
)
from app_gateway.common.clock import to_seconds, to_timestamp
from app_gateway.oauth import (
    TokenError,
    TokenExchangeTokenRequest,
    TokenExchangeTokenResponse,
    TokenExchangeTokenType,
)
from app_gateway.oauth.responses import OauthResponse
from app_gateway.policy import AccessType, AppAccessRule, Client, ClientType, Resource
from app_gateway.session import AccessTokenLog, AuthorizationScope, Session

MAX_ACT_DEPTH = 3


class SubjectToken(NamedTuple):
    sub: str
    aud: str
    client_id: str
    sid: str
    exp: int
    scope: str | None
    act: dict[str, Any] | None


def decode_subject_token(
    subject_token: str,
    keyset: jwk.KeySet,
    issuer: str,
    time: datetime,
) -> SubjectToken | Response:
    registry = jwt.JWTClaimsRegistry(
        now=to_timestamp(time),
        iss={"essential": True, "value": issuer},
        sub={"essential": True},
        aud={"essential": True},
        exp={"essential": True},
    )

    try:
        token = jwt.decode(subject_token, keyset)
        if token.header.get("typ") != "at+jwt":
            return token_error_response(TokenError.INVALID_GRANT)
        registry.validate(token.claims)
    except JoseError, ValueError:
        return token_error_response(TokenError.INVALID_GRANT)

    match token.claims:
        case {
            "sub": str(sub),
            "aud": str(aud),
            "client_id": str(client_id),
            "sid": str(sid),
            "exp": int(exp),
        }:
            pass
        case _:
            return token_error_response(TokenError.INVALID_GRANT)

    scope = token.claims.get("scope")
    act = token.claims.get("act")
    if not isinstance(scope, str | None) or not isinstance(act, dict | None):
        return token_error_response(TokenError.INVALID_GRANT)

    return SubjectToken(sub, aud, client_id, sid, exp, scope, act)


class TokenExchangeGrant(NamedTuple):
    session: Session
    resource: str
    request_scope: AuthorizationScope
    act: dict[str, Any] | None
    expires_at: int


def check_token_exchange(
    subject: SubjectToken,
    maybe_session: Session | None,
    maybe_subject_resource: Resource | None,
    client: Client,
    request: TokenExchangeTokenRequest,
    time: datetime,
    access_token_lifetime: timedelta,
) -> TokenExchangeGrant | Response:
    # Only `resource` targets are supported, and one is required.
    if request.resource is None:
        return token_error_response(TokenError.INVALID_REQUEST)
    if (
        request.audience is not None
        or request.actor_token is not None
        or request.actor_token_type is not None
    ):
        return token_error_response(TokenError.INVALID_REQUEST)

    if (
        maybe_session is None
        or maybe_session.revoked_at is not None
        or maybe_session.user_id != subject.sub
    ):
        return token_error_response(TokenError.INVALID_GRANT)

    is_self = subject.client_id == client.client_id
    # On-behalf-of: the requester's app must own the resource the subject
    # token was issued for, i.e. the requester is that resource server.
    owns_audience = (
        maybe_subject_resource is not None
        and maybe_subject_resource.uri == subject.aud
        and maybe_subject_resource.app_id == client.app_id
    )
    if not is_self and not owns_audience:
        return token_error_response(TokenError.INVALID_GRANT)
    # Acting on behalf of a user requires a client that can keep a secret;
    # public clients may only re-audience their own tokens.
    if not is_self and client.client_type is not ClientType.CONFIDENTIAL:
        return token_error_response(TokenError.UNAUTHORIZED_CLIENT)

    act = subject.act if is_self else _delegate(client, subject.act)
    if _act_depth(act) > MAX_ACT_DEPTH:
        return token_error_response(TokenError.INVALID_REQUEST)

    match narrow_exchange_scope(subject.scope, request.scope):
        case Response() as error_response:
            return error_response
        case scope:
            pass

    return TokenExchangeGrant(
        maybe_session,
        request.resource,
        AuthorizationScope(resource=request.resource, scope=scope),
        act,
        min(to_timestamp(time) + to_seconds(access_token_lifetime), subject.exp),
    )


def exchange_access_type(grant: TokenExchangeGrant, client: Client) -> AccessType:
    # Decided by the token being issued, not by this hop: `act` is never
    # dropped, so a self exchange of a delegated token is still delegated and
    # must not fall back to the actor's direct-access rule.
    if grant.act is not None:
        return AccessType.DELEGATED
    return client_access_type(client)


def narrow_exchange_scope(
    subject_scope: str | None,
    requested_scope: str | None,
) -> str | Response | None:
    # Interim rule: never exceed the subject token's scope. Per app/resource
    # scope grants will further intersect this once they exist.
    if requested_scope is None:
        return subject_scope
    if not set(requested_scope.split()) <= set((subject_scope or "").split()):
        return token_error_response(TokenError.INVALID_SCOPE)
    return requested_scope


def _delegate(client: Client, prior_act: dict[str, Any] | None) -> dict[str, Any]:
    act: dict[str, Any] = {"client_id": client.client_id}
    if prior_act is not None:
        act["act"] = prior_act
    return act


def _act_depth(act: dict[str, Any] | None) -> int:
    depth = 0
    while isinstance(act, dict):
        depth += 1
        act = act.get("act")
    return depth


class CreateTokenExchangeResponseResult(NamedTuple):
    access_token_log: AccessTokenLog
    response: Response


def create_token_exchange_response(
    grant: TokenExchangeGrant,
    client: Client,
    maybe_access_rule: AppAccessRule | None,
    signing_key: jwk.Key,
    jti: str,
    issuer: str,
    time: datetime,
) -> CreateTokenExchangeResponseResult | Response:
    if maybe_access_rule is None:
        return token_error_response(TokenError.INVALID_TARGET)

    header, claims, access_token = create_access_token(
        grant.session,
        client,
        grant.request_scope,
        signing_key,
        jti,
        issuer,
        time,
        grant.expires_at,
        grant.act,
    )

    return CreateTokenExchangeResponseResult(
        AccessTokenLog(
            session_id=grant.session.session_id,
            scope=grant.request_scope,
            header=header,
            claims=claims,
            issued_at=time,
        ),
        OauthResponse(
            TokenExchangeTokenResponse(
                access_token=access_token,
                issued_token_type=TokenExchangeTokenType.ACCESS_TOKEN,
                token_type="Bearer",
                expires_in=grant.expires_at - to_timestamp(time),
                scope=grant.request_scope.scope,
            ),
        ),
    )
