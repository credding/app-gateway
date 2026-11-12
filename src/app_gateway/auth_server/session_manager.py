from datetime import datetime

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app_gateway.common.clock import to_timestamp
from app_gateway.db import async_read, async_write
from app_gateway.db import session_model as model
from app_gateway.session import schema


@async_write
def save_idp_authorization_state(
    sess: Session,
    state: schema.IdpAuthorizationState,
) -> None:
    sess.add(model.IdpAuthorizationState.from_schema(state))


@async_read
def restore_idp_authorization_state(
    sess: Session,
    state_hash: bytes,
) -> schema.IdpAuthorizationState | None:
    state = sess.get(model.IdpAuthorizationState, state_hash)
    if state is None:
        return None
    return state.to_schema()


@async_write
def invalidate_idp_authorization_state(
    sess: Session,
    state_hash: bytes,
) -> bool:
    result = sess.scalars(
        delete(model.IdpAuthorizationState)
        .where(model.IdpAuthorizationState.state_hash == state_hash)
        .returning(model.IdpAuthorizationState.state_hash)
    ).one_or_none()
    return result == state_hash


@async_write
def save_authorization_code_state(
    sess: Session,
    state: schema.AuthorizationCodeState,
) -> None:
    sess.add(model.AuthorizationCodeState.from_schema(state))


@async_read
def restore_authorization_code_state(
    sess: Session,
    code_hash: bytes,
) -> schema.AuthorizationCodeState | None:
    state = sess.get(model.AuthorizationCodeState, code_hash)
    if state is None:
        return None
    return state.to_schema()


@async_write
def invalidate_authorization_code_state(
    sess: Session,
    code_hash: bytes,
    time: datetime,
) -> bool:
    result = sess.scalars(
        update(model.AuthorizationCodeState)
        .where(
            model.AuthorizationCodeState.code_hash == code_hash,
            model.AuthorizationCodeState.invalidated_at.is_(None),
        )
        .values(invalidated_at=to_timestamp(time))
        .returning(model.AuthorizationCodeState.code_hash)
    ).one_or_none()
    return result == code_hash


@async_write
def save_refresh_token_state(
    sess: Session,
    state: schema.RefreshTokenState,
) -> None:
    sess.add(model.RefreshTokenState.from_schema(state))


@async_read
def restore_refresh_token_state(
    sess: Session,
    refresh_token_hash: bytes,
) -> schema.RefreshTokenState | None:
    state = sess.get(model.RefreshTokenState, refresh_token_hash)
    if state is None:
        return None
    return state.to_schema()


@async_write
def invalidate_refresh_token_state(
    sess: Session,
    refresh_token_hash: bytes,
    time: datetime,
) -> bool:
    result = sess.scalars(
        update(model.RefreshTokenState)
        .where(
            model.RefreshTokenState.refresh_token_hash == refresh_token_hash,
            model.RefreshTokenState.invalidated_at.is_(None),
        )
        .values(invalidated_at=to_timestamp(time))
        .returning(model.RefreshTokenState.refresh_token_hash)
    ).one_or_none()
    return result == refresh_token_hash


@async_write
def invalidate_session(
    sess: Session,
    code_hash: bytes,
    time: datetime,
) -> None:
    sess.execute(
        update(model.RefreshTokenState)
        .where(
            model.RefreshTokenState.code_hash == code_hash,
            model.RefreshTokenState.invalidated_at.is_(None),
        )
        .values(invalidated_at=to_timestamp(time))
    )


@async_write
def save_idp_session(
    sess: Session,
    state: schema.IdpSession,
) -> None:
    sess.merge(model.IdpSession.from_schema(state))


@async_read
def restore_idp_session(
    sess: Session,
    client_id: str,
    user_id: str,
    idp_issuer: str,
) -> schema.IdpSession | None:
    session = sess.get(model.IdpSession, (client_id, user_id, idp_issuer))
    if session is None:
        return None
    return session.to_schema()


@async_write
def save_access_token_log(sess: Session, log: schema.AccessTokenLog) -> None:
    sess.add(model.AccessTokenLog.from_schema(log))
