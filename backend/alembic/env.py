from logging.config import fileConfig
import os

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import application metadata for autogenerate support.
from app.db.database import Base
from app.models import User

target_metadata = Base.metadata


def get_database_url() -> str:
    """
    Use the runtime DATABASE_URL when available.

    This is important in Docker because the backend container must
    connect to the PostgreSQL service using the Docker service name
    rather than localhost.
    """
    url = os.getenv("DATABASE_URL")

    if not url:
        url = config.get_main_option("sqlalchemy.url")

    if not url:
        raise RuntimeError(
            "DATABASE_URL is not configured and sqlalchemy.url is empty."
        )

    return url


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""

    url = get_database_url()

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""

    url = get_database_url()

    configuration = config.get_section(
        config.config_ini_section,
        {},
    )

    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()