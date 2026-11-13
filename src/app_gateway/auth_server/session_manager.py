from datetime import datetime
from typing import NamedTuple

from sqlalchemy import delete, select, update

from app_gateway.common.clock import to_timestamp
from app_gateway.common.tokens import hash_token
from app_gateway.db import SessionOps
from app_gateway.db import session_model as model
from app_gateway.oauth import GrantType
from app_gateway.session import schema


class SessionGrantSession(NamedTuple):
    session_grant: schema.SessionGrant
    session: schema.Session


class SessionReadOps(SessionOps):
    def restore_session(
        self, token: str, grant_type: GrantType
    ) -> SessionGrantSession | None:
        result = self.sess.execute(
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
                return SessionGrantSession(
                    session_grant.to_schema(),
                    session.to_schema(),
                )
            case _:
                return None

    def restore_idp_session(self, session: schema.Session) -> schema.IdpSession | None:
        result = self.sess.get(
            model.IdpSession,
            (session.client_id, session.user_id, session.idp_issuer),
        )
        if result is None:
            return None
        return result.to_schema()


class SessionWriteOps(SessionReadOps):
    def save_session(self, session: schema.Session) -> None:
        self.sess.add(model.Session.from_schema(session))

    def revoke_session(self, session_id: str, time: datetime) -> bool:
        result = self.sess.scalars(
            update(model.Session)
            .where(
                model.Session.session_id == session_id,
                model.Session.revoked_at.is_(None),
            )
            .values(revoked_at=to_timestamp(time))
            .returning(model.Session.session_id)
        )
        return result.one_or_none() == session_id

    def extend_session(self, session_id: str, expires_at: datetime) -> bool:
        result = self.sess.scalars(
            update(model.Session)
            .where(
                model.Session.session_id == session_id,
                model.Session.revoked_at.is_(None),
            )
            .values(expires_at=to_timestamp(expires_at))
            .returning(model.Session.session_id)
        )
        return result.one_or_none() == session_id

    def save_session_grant(self, session_grant: schema.SessionGrant) -> None:
        self.sess.add(model.SessionGrant.from_schema(session_grant))

    def invalidate_session_grant(self, token_hash: bytes, time: datetime) -> bool:
        result = self.sess.scalars(
            update(model.SessionGrant)
            .where(
                model.SessionGrant.token_hash == token_hash,
                model.SessionGrant.invalidated_at.is_(None),
            )
            .values(invalidated_at=to_timestamp(time))
            .returning(model.SessionGrant.token_hash)
        )
        return result.one_or_none() == token_hash

    def save_access_token_log(self, log: schema.AccessTokenLog) -> None:
        self.sess.add(model.AccessTokenLog.from_schema(log))

    def save_idp_authorization_state(self, state: schema.IdpAuthorizationState) -> None:
        self.sess.add(model.IdpAuthorizationState.from_schema(state))

    def invalidate_idp_authorization_state(
        self, state_token: str, idp_slug: str
    ) -> schema.IdpAuthorizationState | None:
        result = self.sess.scalars(
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

    def save_idp_session(self, session: schema.IdpSession) -> None:
        self.sess.merge(model.IdpSession.from_schema(session))
