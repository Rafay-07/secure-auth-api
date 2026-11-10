# secure-auth-api

A small Flask authentication API that shows the standard protections a login system needs, with every step commented so it can be read and explained.

| Protection | Where |
|---|---|
| Passwords hashed with scrypt and a random salt | `security.py` |
| Password policy (length, upper, lower, digit) | `security.py` |
| Signed, expiring tokens (HMAC-SHA256) | `security.py` |
| Constant-time comparisons (timing attacks) | `security.py` |
| Per-IP rate limiting | `security.py`, `app.py` |
| Account lockout after 5 failed logins | `app.py` |
| Same error for unknown user and wrong password | `app.py` |
| Parameterized SQL (SQL injection) | `db.py`, `app.py` |
| Role-based access to `/admin/users` | `app.py` |

## Endpoints

- `POST /register` with `{"username", "password"}`
- `POST /login` returns `{"token"}`
- `GET /me` with `Authorization: Bearer <token>`
- `GET /admin/users` (admin role only)

## Run

```bash
pip install -r requirements.txt
python -m pytest -q      # 12 tests
python app.py            # serves on http://127.0.0.1:5000
```

## Limits

Learning project. Tokens are hand-rolled to show how signing works; use a maintained JWT library in production. Rate limits live in memory, so they reset on restart and are per process. Set a real `secret` and serve over HTTPS.
