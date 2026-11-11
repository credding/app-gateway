from datetime import datetime
from typing import Any, Protocol, cast

from sqlalchemy import CursorResult, Result, delete, update
from sqlalchemy.orm import Session, sessionmaker

from app_gateway import session_model as model
from app_gateway import session_schema as schema
from app_gateway.common.clock import to_timestamp
from app_gateway.common.db import read_session, run_read, run_write, write_session


def _affected_one(result: Result[Any]) -> bool:
    # DML statements always produce a CursorResult; Session.execute is typed as Result.
    return cast("CursorResult[Any]", result).rowcount == 1


class _Restorable[S](Protocol):
    def to_schema(self) -> S: ...


class SessionManager:
    def __init__(
        self,
        read_session: sessionmaker[Session] = read_session,
        write_session: sessionmaker[Session] = write_session,
    ) -> None:
        self.read_session = read_session
        self.write_session = write_session

    async def save_idp_authorization_state(
        self, state: schema.IdpAuthorizationState
    ) -> None:
        await run_write(
            lambda: self._save(model.IdpAuthorizationState.from_schema(state))
        )

    async def restore_idp_authorization_state(
        self, state_hash: bytes
    ) -> schema.IdpAuthorizationState | None:
        return await run_read(
            lambda: self._restore(model.IdpAuthorizationState, state_hash)
        )

    async def invalidate_idp_authorization_state(self, state_hash: bytes) -> bool:
        return await run_write(
            lambda: self._invalidate_idp_authorization_state(state_hash)
        )

    async def save_authorization_code_state(
        self, state: schema.AuthorizationCodeState
    ) -> None:
        await run_write(
            lambda: self._save(model.AuthorizationCodeState.from_schema(state))
        )

    async def restore_authorization_code_state(
        self, code_hash: bytes
    ) -> schema.AuthorizationCodeState | None:
        return await run_read(
            lambda: self._restore(model.AuthorizationCodeState, code_hash)
        )

    async def invalidate_authorization_code_state(
        self, code_hash: bytes, time: datetime
    ) -> bool:
        return await run_write(
            lambda: self._invalidate_authorization_code_state(code_hash, time)
        )

    async def save_refresh_token_state(self, state: schema.RefreshTokenState) -> None:
        await run_write(lambda: self._save(model.RefreshTokenState.from_schema(state)))

    async def restore_refresh_token_state(
        self, refresh_token_hash: bytes
    ) -> schema.RefreshTokenState | None:
        return await run_read(
            lambda: self._restore(model.RefreshTokenState, refresh_token_hash)
        )

    async def invalidate_refresh_token_state(
        self, refresh_token_hash: bytes, time: datetime
    ) -> bool:
        return await run_write(
            lambda: self._invalidate_refresh_token_state(refresh_token_hash, time)
        )

    async def invalidate_session(self, code_hash: bytes, time: datetime) -> None:
        return await run_write(lambda: self._invalidate_session(code_hash, time))

    async def save_access_token_log(self, log: schema.AccessTokenLog) -> None:
        await run_write(lambda: self._save(model.AccessTokenLog.from_schema(log)))

    def _save(self, row: model.Base) -> None:
        with self.write_session.begin() as session:
            session.add(row)

    def _restore[S](self, row_type: type[_Restorable[S]], key: bytes) -> S | None:
        with self.read_session() as session:
            row = session.get(row_type, key)
            return None if row is None else row.to_schema()

    def _invalidate_idp_authorization_state(self, state_hash: bytes) -> bool:
        with self.write_session.begin() as session:
            result = session.execute(
                delete(model.IdpAuthorizationState).where(
                    model.IdpAuthorizationState.state_hash == state_hash
                )
            )
            return _affected_one(result)

    def _invalidate_authorization_code_state(
        self, code_hash: bytes, time: datetime
    ) -> bool:
        with self.write_session.begin() as session:
            result = session.execute(
                update(model.AuthorizationCodeState)
                .where(
                    model.AuthorizationCodeState.code_hash == code_hash,
                    model.AuthorizationCodeState.invalidated_at.is_(None),
                )
                .values(invalidated_at=to_timestamp(time))
            )
            return _affected_one(result)

    def _invalidate_refresh_token_state(
        self, refresh_token_hash: bytes, time: datetime
    ) -> bool:
        with self.write_session.begin() as session:
            result = session.execute(
                update(model.RefreshTokenState)
                .where(
                    model.RefreshTokenState.refresh_token_hash == refresh_token_hash,
                    model.RefreshTokenState.invalidated_at.is_(None),
                )
                .values(invalidated_at=to_timestamp(time))
            )
            return _affected_one(result)

    def _invalidate_session(self, code_hash: bytes, time: datetime) -> None:
        with self.write_session.begin() as session:
            session.execute(
                update(model.RefreshTokenState)
                .where(
                    model.RefreshTokenState.code_hash == code_hash,
                    model.RefreshTokenState.invalidated_at.is_(None),
                )
                .values(invalidated_at=to_timestamp(time))
            )
