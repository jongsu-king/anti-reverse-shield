# SPDX-License-Identifier: MIT
"""
Server-side request verification reference.

This is the ONLY durable layer: it runs on hardware the attacker does not
control, so it cannot be patched or lied to from the client. Every client-side
check in this repo is advisory; this is the real boundary.

Protocol (client -> server), all over pinned TLS:
    headers:
        X-Nonce      : 32 random hex chars, single-use
        X-Timestamp  : unix seconds
        X-Signature  : hex HMAC-SHA256( body || nonce || timestamp )
    body: the request bytes (optionally with sensitive fields E2E-encrypted)

The server rejects: bad signature, stale timestamp, or replayed nonce.
Run `python3 -m pytest` style check at the bottom via `python3 verify.py`.
"""
import hmac
import hashlib
import time

CLOCK_SKEW_SECONDS = 30          # reject requests older/newer than this
_seen_nonces: dict[str, float] = {}  # nonce -> expiry (use Redis in production)


def sign(mac_key: bytes, body: bytes, nonce: str, timestamp: int) -> str:
    msg = body + nonce.encode() + str(timestamp).encode()
    return hmac.new(mac_key, msg, hashlib.sha256).hexdigest()


def verify(mac_key: bytes, body: bytes, nonce: str, timestamp: int,
           signature: str, now: int | None = None) -> tuple[bool, str]:
    now = int(time.time()) if now is None else now

    if abs(now - timestamp) > CLOCK_SKEW_SECONDS:
        return False, "stale timestamp"

    # purge expired nonces, then reject replays
    for n, exp in list(_seen_nonces.items()):
        if exp < now:
            del _seen_nonces[n]
    if nonce in _seen_nonces:
        return False, "replayed nonce"

    expected = sign(mac_key, body, nonce, timestamp)
    if not hmac.compare_digest(expected, signature):  # constant-time
        return False, "bad signature"

    _seen_nonces[nonce] = now + CLOCK_SKEW_SECONDS
    return True, "ok"


if __name__ == "__main__":
    key = b"server-only-secret-never-shipped-to-client"
    body = b'{"action":"unlock_feature","sku":"pro"}'
    nonce = "0123456789abcdef0123456789abcdef"
    ts = int(time.time())
    sig = sign(key, body, nonce, ts)

    ok, why = verify(key, body, nonce, ts, sig)
    assert ok, why
    # replay must fail
    ok2, why2 = verify(key, body, nonce, ts, sig)
    assert not ok2 and why2 == "replayed nonce", why2
    # tamper must fail
    ok3, _ = verify(key, body + b"x", "ffffffffffffffffffffffffffffffff", ts, sig)
    assert not ok3
    print("verify.py self-test: PASS")
