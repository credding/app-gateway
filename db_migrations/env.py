import logging

from alembic import context
from sqlalchemy import create_engine, pool

from app_gateway.db import POLICY_DATABASE
from app_gateway.db import session_model as _session_model  # noqa: F401 (registers tables)
from app_gateway.db.policy_model import Base

logging.basicConfig(format="%(levelname)-5.5s [%(name)s] %(message)s")
logging.getLogger("alembic").setLevel(logging.INFO)

URL = f"sqlite:///{POLICY_DATABASE}"


def run_migrations_offline() -> None:
    context.configure(
        url=URL,
        target_metadata=Base.metadata,
        literal_binds=True,
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(URL, poolclass=pool.NullPool)

    with engine.connect() as connection:
        # SQLite can't ALTER most things in place; batch mode recreates tables.
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
