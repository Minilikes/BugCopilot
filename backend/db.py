"""SQLite database setup via SQLModel."""

from sqlmodel import SQLModel, create_engine, Session
from backend import config

DATABASE_URL = f"sqlite:///{config.DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def create_db_and_tables():
    """Called at startup to create all tables if they don't exist."""
    # Import all models so SQLModel registers them
    from backend.models import scope, finding, target, recon  # noqa: F401
    SQLModel.metadata.create_all(engine)


def get_session():
    """FastAPI dependency that yields a database session."""
    with Session(engine) as session:
        yield session
