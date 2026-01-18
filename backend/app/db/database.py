import sqlite3
import os
from contextlib import contextmanager
from pathlib import Path
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_schema_path() -> str:
    """Get the path to schema.sql file."""
    return os.path.join(os.path.dirname(__file__), "schema.sql")


def init_database() -> None:
    """Initialize database and create tables if they don't exist."""
    db_path = Path(settings.db_path)
    
    # Create directory if it doesn't exist
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Read schema
    schema_path = get_schema_path()
    with open(schema_path, 'r') as f:
        schema_sql = f.read()
    
    # Execute schema
    with get_db_connection() as conn:
        conn.executescript(schema_sql)
        conn.commit()
    
    logger.info(f"Database initialized at {settings.db_path}")


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

