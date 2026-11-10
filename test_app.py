import time

import pytest

from app import MAX_FAILS, create_app
from security import (RateLimiter, hash_password, make_token, password_problems,
                      read_token, verify_password)

GOOD = "Sturdy-Pass123"


@pytest.fixture
def client():
    return create_app(rate_limit=1000).test_client()


def register(c, name="ana", pw=GOOD):
    return c.post("/register", json={"username": name, "password": pw})


def token(c, name="ana", pw=GOOD):
    return c.post("/login", json={"username": name, "password": pw}).get_json()["token"]


def test_hash_is_salted_and_verifies():
    a, b = hash_password(GOOD), hash_password(GOOD)
    assert a != b and verify_password(GOOD, a) and not verify_password("wrong", a)


def test_password_policy():
    assert password_problems(GOOD) == []
    assert len(password_problems("short")) >= 3


def test_token_roundtrip_tamper_and_expiry():
    t = make_token({"sub": 1}, "s")
    assert read_token(t, "s")["sub"] == 1
    assert read_token(t, "other-secret") is None
    body, sig = t.split(".")
    assert read_token(body + "." + sig[:-2] + "AA", "s") is None
    assert read_token(make_token({"sub": 1}, "s", ttl_seconds=-1), "s") is None


def test_rate_limiter_window():
    now = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: now[0])
    assert rl.allow("k") and rl.allow("k") and not rl.allow("k")
    now[0] = 11
    assert rl.allow("k")


def test_register_login_me(client):
    assert register(client).status_code == 201
    assert register(client).status_code == 409
    me = client.get("/me", headers={"Authorization": "Bearer " + token(client)})
    assert me.get_json() == {"username": "ana", "role": "user"}


def test_weak_password_rejected(client):
    r = register(client, pw="abc")
    assert r.status_code == 400 and r.get_json()["details"]


def test_same_error_for_unknown_user_and_wrong_password(client):
    register(client)
    a = client.post("/login", json={"username": "ana", "password": "Nope-Nope-123"})
    b = client.post("/login", json={"username": "ghost", "password": "Nope-Nope-123"})
    assert a.status_code == b.status_code == 401 and a.get_json() == b.get_json()


def test_lockout_after_repeated_failures(client):
    register(client)
    for _ in range(MAX_FAILS):
        client.post("/login", json={"username": "ana", "password": "bad-Pass-1234"})
    # even the right password is refused while locked
    assert client.post("/login", json={"username": "ana", "password": GOOD}).status_code == 423


def test_sql_injection_attempt_is_just_a_wrong_name(client):
    r = client.post("/login", json={"username": "' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_admin_route_needs_admin_role(client):
    register(client)
    h = {"Authorization": "Bearer " + token(client)}
    assert client.get("/admin/users", headers=h).status_code == 403
    assert client.get("/admin/users").status_code == 401


def test_admin_can_list_users():
    app = create_app(rate_limit=1000)
    c = app.test_client()
    register(c)
    app.conn.execute("UPDATE users SET role='admin' WHERE username='ana'"); app.conn.commit()
    r = c.get("/admin/users", headers={"Authorization": "Bearer " + token(c)})
    assert r.status_code == 200 and r.get_json()["users"][0]["username"] == "ana"


def test_global_rate_limit():
    c = create_app(rate_limit=3).test_client()
    codes = [c.get("/me").status_code for _ in range(5)]
    assert codes[:3] == [401] * 3 and codes[3:] == [429, 429]
