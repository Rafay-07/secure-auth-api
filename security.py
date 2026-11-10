"""Security helpers: password hashing, signed tokens, password policy, rate limiting.

Everything here uses only the Python standard library so each step is visible
and can be explained: hashlib.scrypt for passwords, hmac + sha256 for tokens.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time


# ---------- passwords ----------
def hash_password(password: str) -> str:
    """Hash with scrypt (a memory-hard KDF, so GPU guessing is expensive).
    A random 16-byte salt means two users with the same password get different hashes."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    # compare_digest takes the same time whether the first or last byte differs,
    # which stops timing attacks.
    return hmac.compare_digest(digest.hex(), digest_hex)


def password_problems(password: str) -> list[str]:
    """Return a list of reasons the password is too weak (empty list = acceptable)."""
    problems = []
    if len(password) < 10:
        problems.append("must be at least 10 characters")
    if not re.search(r"[a-z]", password):
        problems.append("needs a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("needs an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("needs a digit")
    return problems


# ---------- tokens ----------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(payload: dict, secret: str, ttl_seconds: int = 900) -> str:
    """Create 'body.signature'. The signature proves the server issued it and nobody edited it.
    The token is signed, NOT encrypted: never put secrets in the payload."""
    body = dict(payload, exp=int(time.time()) + ttl_seconds)
    body_b64 = _b64(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body_b64.encode(), hashlib.sha256).digest()
    return f"{body_b64}.{_b64(sig)}"


def read_token(token: str, secret: str) -> dict | None:
    """Return the payload if the signature is valid and the token has not expired, else None."""
    try:
        body_b64, sig_b64 = token.split(".")
        expected = hmac.new(secret.encode(), body_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64(expected), sig_b64):
            return None
        padded = body_b64 + "=" * (-len(body_b64) % 4)
        body = json.loads(base64.urlsafe_b64decode(padded))
        return body if body["exp"] >= time.time() else None
    except (ValueError, KeyError):
        return None


# ---------- rate limiting ----------
class RateLimiter:
    """Sliding window: at most `limit` hits per `window` seconds for each key."""

    def __init__(self, limit: int, window: float, clock=time.time):
        self.limit, self.window, self.clock = limit, window, clock
        self.hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        recent = [t for t in self.hits.get(key, []) if now - t < self.window]
        if len(recent) >= self.limit:
            self.hits[key] = recent
            return False
        recent.append(now)
        self.hits[key] = recent
        return True
