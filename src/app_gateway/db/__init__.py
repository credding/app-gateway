from collections.abc import Callable, Coroutine
from functools import partial
from sqlite3 import LEGACY_TRANSACTION_CONTROL
from typing import Concatenate

from anyio import CapacityLimiter, to_thread
from sqlalchemy import Connection, create_engine
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.event import listens_for
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

from app_gateway.settings import DATA_DIR

_POLICY_DATABASE = f"{DATA_DIR}/policy.db"


_READ_TOKENS = 10
_WRITE_TOKENS = 1


_read_engine = create_engine(
    f"sqlite:///file:{_POLICY_DATABASE}?uri=true&mode=ro",
    pool_size=_READ_TOKENS,
    max_overflow=0,
    connect_args={
        "check_same_thread": False,
        "autocommit": False,
    },
)


_write_engine = create_engine(
    f"sqlite:///file:{_POLICY_DATABASE}?uri=true",
    pool_size=_WRITE_TOKENS,
    max_overflow=0,
    connect_args={
        "isolation_level": None,
        "check_same_thread": False,
        "autocommit": LEGACY_TRANSACTION_CONTROL,
    },
)


@listens_for(_write_engine, "connect")
def _do_connect_write(
    dbapi_connection: DBAPIConnection,
    connection_record: ConnectionPoolEntry,  # ruff: ignore[unused-function-argument]
) -> None:
    dbapi_connection.execute("PRAGMA journal_mode=WAL")
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


@listens_for(_write_engine, "begin")
def _do_begin_write(conn: Connection) -> None:
    conn.exec_driver_sql("BEGIN IMMEDIATE")


_read_limiter = CapacityLimiter(_READ_TOKENS)
_write_limiter = CapacityLimiter(_WRITE_TOKENS)


_read_session = sessionmaker(_read_engine)
_write_session = sessionmaker(_write_engine)


def _async_in_session[**P, R](
    limiter: CapacityLimiter,
    session: sessionmaker[Session],
    fn: Callable[Concatenate[Session, P], R],
) -> Callable[P, Coroutine[None, None, R]]:
    def run_sync(*args: P.args, **kwargs: P.kwargs) -> Coroutine[None, None, R]:
        def run_with_session() -> R:
            with session.begin() as sess:
                return fn(sess, *args, **kwargs)

        return to_thread.run_sync(run_with_session, limiter=limiter)

    return run_sync


async_read = partial(_async_in_session, _read_limiter, _read_session)
async_write = partial(_async_in_session, _write_limiter, _write_session)
