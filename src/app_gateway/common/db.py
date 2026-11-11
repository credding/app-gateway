from collections.abc import Callable
from sqlite3 import LEGACY_TRANSACTION_CONTROL

from anyio import CapacityLimiter, to_thread
from sqlalchemy import Connection, create_engine
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.event import listens_for
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

from app_gateway.settings import DATA_DIR

POLICY_DATABASE = f"{DATA_DIR}/policy.db"


READ_TOKENS = 10
WRITE_TOKENS = 1

read_engine = create_engine(
    f"sqlite:///file:{POLICY_DATABASE}?uri=true&mode=ro",
    pool_size=READ_TOKENS,
    max_overflow=0,
    connect_args={
        "check_same_thread": False,
        "autocommit": False,
    },
)


write_engine = create_engine(
    f"sqlite:///file:{POLICY_DATABASE}?uri=true",
    pool_size=WRITE_TOKENS,
    max_overflow=0,
    connect_args={
        "isolation_level": None,
        "check_same_thread": False,
        "autocommit": LEGACY_TRANSACTION_CONTROL,
    },
)


@listens_for(write_engine, "connect")
def do_connect_write(
    dbapi_connection: DBAPIConnection,
    connection_record: ConnectionPoolEntry,  # ruff: ignore[unused-function-argument]
) -> None:
    dbapi_connection.execute("PRAGMA journal_mode=WAL")
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


@listens_for(write_engine, "begin")
def do_begin_write(conn: Connection) -> None:
    conn.exec_driver_sql("BEGIN IMMEDIATE")


read_session = sessionmaker(read_engine)
write_session = sessionmaker(write_engine)

read_limiter = CapacityLimiter(READ_TOKENS)
write_limiter = CapacityLimiter(WRITE_TOKENS)


async def run_read[T](fn: Callable[[], T]) -> T:
    return await to_thread.run_sync(fn, limiter=read_limiter)


async def run_write[T](fn: Callable[[], T]) -> T:
    return await to_thread.run_sync(fn, limiter=write_limiter)
