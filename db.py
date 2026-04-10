import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection():
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise ValueError("No se encontró la variable DATABASE_URL en Render")

    return psycopg2.connect(
        database_url,
        cursor_factory=RealDictCursor
    )