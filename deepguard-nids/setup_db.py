"""
DeepGuard NIDS - Database Setup Script
Automatically creates the MySQL database in XAMPP if it doesn't exist,
then falls back to SQLite if MySQL is unavailable.
"""
import pymysql
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def create_mysql_database():
    """Create deepguard_db in XAMPP MySQL if it doesn't exist."""
    try:
        conn = pymysql.connect(host="localhost", port=3306, user="root", password="")
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS deepguard_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.execute("SHOW DATABASES LIKE 'deepguard_db'")
        if cursor.fetchone():
            print("[SETUP] MySQL database 'deepguard_db' is ready.")
        conn.close()
        return True
    except Exception as e:
        print(f"[SETUP] MySQL not available: {e}")
        print("[SETUP] Will use SQLite as fallback.")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("  DeepGuard NIDS - Database Setup")
    print("=" * 50)

    mysql_ok = create_mysql_database()

    if not mysql_ok:
        os.environ["DB_TYPE"] = "sqlite"
        print("[SETUP] Set DB_TYPE=sqlite")

    # Now initialize tables
    from backend.database.models import init_db
    init_db()
    print("[SETUP] Database setup complete!")
