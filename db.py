"""SQLite storage. Every query uses ? placeholders, never string formatting,
so user input cannot change the SQL (this is what stops SQL injection)."""
import sqlite3


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until REAL NOT NULL DEFAULT 0)""")
    return db
