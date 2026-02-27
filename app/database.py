import sqlite3
from app.config import DATABASE_PATH


def get_db():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT DEFAULT 'user',
            reset_token TEXT
        );

        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            status TEXT,
            owner_id INTEGER,
            attachment TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER,
            user_id INTEGER,
            content TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            user_id INTEGER,
            details TEXT,
            created_at TEXT
        );
        """
    )
    conn.commit()

    # VULNERABILITY: Hardcoded default admin credentials
    cursor.execute(
        "INSERT OR IGNORE INTO users(username, email, password, role) VALUES ('admin', 'admin@local', '0192023a7bbd73250516f069df18b500', 'admin')"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users(username, email, password, role) VALUES ('alice', 'alice@local', '7c90f2dc82aa5dd4501132f6d074a53a', 'user')"
    )
    conn.commit()
