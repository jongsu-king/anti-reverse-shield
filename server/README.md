# server — the durable boundary

Client-side protection buys time; **server-side authority is the real defense.**
`verify.py` is a reference for authenticating client requests so that a cracked
or instrumented client still cannot forge, replay, or tamper with requests.

- **HMAC-SHA256(body ‖ nonce ‖ timestamp)** — integrity + authenticity.
- **nonce** (single-use) — blocks replay.
- **timestamp** (± skew window) — blocks delayed replay.
- Combine with TLS **certificate pinning** on the client and **E2E payload
  encryption** so a stripped pin still yields ciphertext.

Design so the decision lives here: return a short-lived, scoped, server-signed
capability token instead of a client-side boolean. There is then nothing on the
client to NOP.

Run the self-test:
```bash
python3 server/verify.py
```
