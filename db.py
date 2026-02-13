import mysql.connector
from mysql.connector import pooling
from config import Config

_pool = None


def get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="secureauth_pool",
            pool_size=10,
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            autocommit=False,
        )
    return _pool


def get_connection():
    return get_pool().get_connection()


def query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """Run a single SQL query and return results."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, params or ())
        if commit:
            conn.commit()
            return cursor.lastrowid
        if fetchone:
            return cursor.fetchone()
        if fetchall:
            return cursor.fetchall()
        return None
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
