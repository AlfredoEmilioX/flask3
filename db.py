import os
import psycopg2

def get_connection():
    database_url = os.getenv("DATABASE_URL")

    # Si está en Render / Supabase
    if database_url:
        return psycopg2.connect(database_url)

    # Si estás en local con MySQL/XAMPP
    import pymysql
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="dietas"
    )