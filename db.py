import os
import psycopg2
import pymysql


def get_connection():
    database_url = os.getenv("DATABASE_URL")

    # 👉 SI estás en Render / Supabase
    if database_url:
        return psycopg2.connect(database_url)

    # 👉 SI estás en local (XAMPP)
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="flask_db",
        cursorclass=pymysql.cursors.DictCursor
    )