from __future__ import annotations

import hashlib
import os
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
    extended, new_sig = hasher.extend(
        data_to_append.decode("latin1"),
        original_message.decode("latin1"),
        secret_length_guess,
        hex_digest,
    )
    return extended.encode("latin1"), new_sig


def construct_extended_message(
    original_message: bytes,
    data_to_append: bytes,
    secret_length_guess: int,
    block_size: int = 64,
) -> bytes:
    """
    Build original || padding(secret||original) || data_to_append without knowing the secret.
    This matches what an attacker would send after length extension.
    """
    total_len = secret_length_guess + len(original_message)
    ml_bits = total_len * 8
    # MD-style padding
    pad = b"\x80"
    pad += b"\x00" * ((-(total_len + 1 + 8)) % block_size)
    pad += ml_bits.to_bytes(8, byteorder="big")
    return original_message + pad + data_to_append


def simulate_length_extension_verification(
    original_message: bytes,
    data_to_append: bytes,
    secret_key: bytes,
    algorithm: str = "sha256",
    secret_length_guess: Optional[int] = None,
) -> Tuple[bytes, str, str]:
    """
    Education-only simulation of length extension verification. We compute:
    - server_digest = H(secret || original)
    - attacker_sends = original || pad || append
    - server_verifies H(secret || attacker_sends) == extended_digest
    Returns (attacker_sends, server_digest_hex, extended_server_digest_hex)
    """
    algo = algorithm.lower()
    hfun = getattr(hashlib, algo)
    if secret_length_guess is None:
        secret_length_guess = len(secret_key)
    attacker_msg = construct_extended_message(original_message, data_to_append, secret_length_guess, 64 if algo != "sha512" else 128)
    server_digest = hfun(secret_key + original_message).hexdigest()
    extended_server_digest = hfun(secret_key + attacker_msg).hexdigest()
    return attacker_msg, server_digest, extended_server_digest


# Legacy placeholder; prefer true_hmac_sha256

def hmac_sha256(key: bytes, message: bytes) -> str:
    return hashlib.new("sha256", message, usedforsecurity=True).hexdigest()

import hmac as _py_hmac

def true_hmac_sha256(key: bytes, message: bytes) -> str:
    return _py_hmac.new(key, message, digestmod=hashlib.sha256).hexdigest()
