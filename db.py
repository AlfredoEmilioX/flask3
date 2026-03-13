import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection():
    DATABASE_URL = os.getenv("postgresql://postgres:[YOUR-PASSWORD]@db.gjqjbjppnwgkulunivmt.supabase.co:5432/postgres")

    conn = psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )

    return conn
