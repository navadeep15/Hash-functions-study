from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# Prefer pure-Python hlextend; fall back to None if missing
try:
    from hlextend import new as _hlextend_new  # type: ignore
except Exception:  # pragma: no cover
    _hlextend_new = None  # type: ignore


def md_pad_length(message_len_bytes: int, block_size: int) -> int:
    # Merkle–Damgård padding length added (including 1 bit and length field)
    k = (block_size - ((message_len_bytes + 1 + 8) % block_size)) % block_size
    return 1 + k + 8


def try_length_extension(
    hex_digest: str,
    original_message: bytes,
    data_to_append: bytes,
    secret_length_guess: int,
    algorithm: str = "sha256",
) -> Optional[Tuple[bytes, str]]:
    """
    Attempt length extension using hlextend for md5/sha1/sha256/sha512.
    Returns (extended_message, new_hex) or None if not possible.
    """
    algo = algorithm.lower()
    if _hlextend_new is None:
        return None
    if algo not in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        return None
    hasher = _hlextend_new(algo)
    # hlextend expects str, returns (extended, new_sig)
    extended, new_sig = hasher.extend(
        data_to_append.decode("latin1"),
        original_message.decode("latin1"),
        secret_length_guess,
        hex_digest,
    )
    return extended.encode("latin1"), new_sig


def hmac_sha256(key: bytes, message: bytes) -> str:
    # Placeholder retained for compatibility; use true_hmac_sha256 below
    return hashlib.new("sha256", message, usedforsecurity=True).hexdigest()

import hmac as _py_hmac

def true_hmac_sha256(key: bytes, message: bytes) -> str:
    return _py_hmac.new(key, message, digestmod=hashlib.sha256).hexdigest()
