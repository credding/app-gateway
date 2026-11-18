from datetime import datetime
from typing import NamedTuple

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app_gateway.common.clock import to_timestamp
from app_gateway.common.tokens import hash_token
from app_gateway.db import async_read, async_write
from app_gateway.db import session_model as model
from app_gateway.oauth import GrantType
from app_gateway.session import schema


class RestoreSessionGrantResult[T: schema.SessionGrant](NamedTuple):
    session_grant: T
    session: schema.Session
    maybe_idp_session: schema.IdpSession | None


class RedeemSessionGrantResult[T: schema.SessionGrant](NamedTuple):
    session_grant: T
    session: schema.Session
    replayed: bool


def _restore_session(
    sess: Session, token: str, grant_type: GrantType
) -> tuple[schema.SessionGrant, schema.Session] | None:
    result = sess.execute(
        select(model.SessionGrant, model.Session)
        .where(
            model.SessionGrant.token_hash == hash_token(token),
            model.SessionGrant.grant_type == grant_type,
        )
        .join(
            model.Session,
            model.Session.session_id == model.SessionGrant.session_id,
        )
    )
    match result.one_or_none():
        case (session_grant, session):
            return session_grant.to_schema(), session.to_schema()
        case _:
            return None


def _restore_idp_session(
    sess: Session, session: schema.Session
) -> schema.IdpSession | None:
    result = sess.get(
        model.IdpSession,
        (session.client_id, session.user_id, session.idp_issuer),
    )
    if result is None:
        return None
    return result.to_schema()


def _invalidate_session_grant(sess: Session, token_hash: bytes, time: datetime) -> bool:
    result = sess.scalars(
        update(model.SessionGrant)
        .where(
            model.SessionGrant.token_hash == token_hash,
            model.SessionGrant.invalidated_at.is_(None),
        )
        .values(invalidated_at=to_timestamp(time))
        .returning(model.SessionGrant.token_hash)
    )
    return result.one_or_none() == token_hash


@async_read
def restore_session_grant(
    sess: Session, token: str, grant_type: GrantType
) -> RestoreSessionGrantResult | None:
    restored = _restore_session(sess, token, grant_type)
    if restored is None:
        return None

    session_grant, session = restored
    return RestoreSessionGrantResult(
        session_grant, session, _restore_idp_session(sess, session)
    )


@async_write
def redeem_session_grant(
    sess: Session, token: str, grant_type: GrantType, time: datetime
) -> RedeemSessionGrantResult | None:
    restored = _restore_session(sess, token, grant_type)
    if restored is None:
        return None

    session_grant, session = restored
    invalidated = _invalidate_session_grant(sess, session_grant.token_hash, time)

    return RedeemSessionGrantResult(session_grant, session, not invalidated)


@async_write
def initialize_session(
    sess: Session,
    idp_session: schema.IdpSession,
    session: schema.Session,
    session_grant: schema.SessionGrant,
) -> None:
    sess.merge(model.IdpSession.from_schema(idp_session))
    sess.add(model.Session.from_schema(session))
    sess.add(model.SessionGrant.from_schema(session_grant))


@async_write
def revoke_session(sess: Session, session_id: str, time: datetime) -> bool:
    result = sess.scalars(
        update(model.Session)
        .where(
            model.Session.session_id == session_id,
            model.Session.revoked_at.is_(None),
        )
        .values(revoked_at=to_timestamp(time))
        .returning(model.Session.session_id)
    )
    return result.one_or_none() == session_id


@async_write
def save_issued_tokens(
    sess: Session,
    access_token_log: schema.AccessTokenLog,
    refresh_grant: schema.SessionGrant,
) -> None:
    sess.add(model.AccessTokenLog.from_schema(access_token_log))
    sess.add(model.SessionGrant.from_schema(refresh_grant))


@async_write
def save_idp_session(sess: Session, idp_session: schema.IdpSession) -> None:
    sess.merge(model.IdpSession.from_schema(idp_session))


@async_write
def save_idp_authorization_state(
    sess: Session, state: schema.IdpAuthorizationState
) -> None:
    sess.add(model.IdpAuthorizationState.from_schema(state))


@async_write
def invalidate_idp_authorization_state(
    sess: Session, state_token: str, idp_slug: str
) -> schema.IdpAuthorizationState | None:
    result = sess.scalars(
        delete(model.IdpAuthorizationState)
        .where(
            model.IdpAuthorizationState.state_hash == hash_token(state_token),
            model.IdpAuthorizationState.idp_slug == idp_slug,
        )
        .returning(model.IdpAuthorizationState)
    )
    state = result.one_or_none()
    if state is None:
        return None
    return state.to_schema()
