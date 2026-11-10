"""Small authentication API (Flask).

Endpoints: POST /register, POST /login, GET /me, GET /admin/users.
Protections: scrypt password hashing, password policy, signed expiring tokens,
per-IP rate limiting, account lockout after repeated failures, role checks,
and identical error messages for unknown user vs wrong password.
"""
import time

from flask import Flask, jsonify, request

import db as database
from security import (RateLimiter, hash_password, make_token, password_problems,
                      read_token, verify_password)

MAX_FAILS = 5          # failed logins before the account locks
LOCK_SECONDS = 300     # how long it stays locked


def create_app(db_path=":memory:", secret="change-me-in-production", rate_limit=20):
    app = Flask(__name__)
    conn = database.connect(db_path)
    limiter = RateLimiter(rate_limit, 60)

    def current_user():
        """Read 'Authorization: Bearer <token>' and return the user row, or None."""
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        payload = read_token(header[7:], secret)
        if not payload:
            return None
        return conn.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()

    @app.before_request
    def throttle():
        if not limiter.allow(request.remote_addr or "?"):
            return jsonify(error="too many requests"), 429

    @app.post("/register")
    def register():
        data = request.get_json(silent=True) or {}
        username, password = data.get("username", ""), data.get("password", "")
        if not username or len(username) > 40:
            return jsonify(error="username required (max 40 characters)"), 400
        problems = password_problems(password)
        if problems:
            return jsonify(error="weak password", details=problems), 400
        try:
            conn.execute("INSERT INTO users(username, pw_hash) VALUES (?,?)",
                         (username, hash_password(password)))
            conn.commit()
        except Exception:                      # UNIQUE constraint: name already taken
            return jsonify(error="username taken"), 409
        return jsonify(ok=True), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        user = conn.execute("SELECT * FROM users WHERE username=?", (data.get("username", ""),)).fetchone()
        if user and user["locked_until"] > time.time():
            return jsonify(error="account locked, try later"), 423
        if not user or not verify_password(data.get("password", ""), user["pw_hash"]):
            if user:                           # count the failure, lock after MAX_FAILS
                fails = user["failed_logins"] + 1
                lock = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
                conn.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                             (0 if lock else fails, lock, user["id"]))
                conn.commit()
            return jsonify(error="invalid credentials"), 401   # same message either way
        conn.execute("UPDATE users SET failed_logins=0 WHERE id=?", (user["id"],))
        conn.commit()
        return jsonify(token=make_token({"sub": user["id"], "role": user["role"]}, secret))

    @app.get("/me")
    def me():
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        return jsonify(username=user["username"], role=user["role"])

    @app.get("/admin/users")
    def admin_users():
        user = current_user()
        if not user:
            return jsonify(error="unauthorized"), 401
        if user["role"] != "admin":
            return jsonify(error="forbidden"), 403
        rows = conn.execute("SELECT username, role FROM users ORDER BY id").fetchall()
        return jsonify(users=[dict(r) for r in rows])

    app.conn = conn        # exposed so tests can promote a user to admin
    return app


if __name__ == "__main__":
    create_app("auth.db").run(debug=False)
