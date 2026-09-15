"""
Server-side security helpers for SefiBox.

Important design note
----------------------
SefiBox performs *encryption and decryption in the browser* using the
Web Crypto API (see static/js/crypto.js). The Django server:

  * never sees plaintext secrets,
  * never sees the AES-GCM decryption key (it lives only in the URL
    fragment, which browsers do not send to the server),
  * only stores ciphertext + IV (both meaningless without the key).

This module handles the pieces that *are* the server's responsibility:
generating unguessable share tokens, hashing them for storage/lookup
(so a database leak doesn't hand out usable links), and basic
ciphertext validation.
"""
import base64
import binascii
import hashlib
import hmac
import secrets

# 32 bytes of randomness, URL-safe base64 encoded -> ~43 chars.
TOKEN_BYTES = 32


def generate_share_token() -> str:
    """Return a cryptographically secure, URL-safe random token.

    This token is given to the *recipient* as part of the /s/<token>
    URL. It is never stored in plaintext server-side -- only its hash
    is persisted, so possession of the database alone is not enough
    to access any share.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Deterministically hash a share token for storage/lookup.

    SHA-256 is sufficient here (not a password hash) because the
    input is a full-entropy 256-bit random token, not a
    human-memorable secret subject to brute force / dictionary
    attack.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(token: str, token_hash: str) -> bool:
    """Constant-time comparison of a raw token against a stored hash."""
    return hmac.compare_digest(hash_token(token), token_hash)


def is_valid_base64(value: str, max_length: int) -> bool:
    """Validate that `value` looks like base64 ciphertext/IV data.

    We never attempt to decrypt or inspect the *contents* server-side
    (we can't -- we don't have the key), but we do validate that what
    we're storing is well-formed base64 within a sane size limit, to
    avoid persisting garbage or oversized blobs.
    """
    if not value or len(value) > max_length:
        return False
    try:
        # validate=True rejects non-alphabet characters.
        base64.b64decode(value, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def client_ip(request) -> str:
    """Best-effort client IP extraction, respecting a trusted proxy header.

    In production, ensure only your load balancer/reverse proxy can set
    X-Forwarded-For, otherwise this can be spoofed by clients.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
