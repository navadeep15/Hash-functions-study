import hashlib
from typing import Callable, Dict

SUPPORTED_HASHES: Dict[str, Callable[[], "hashlib._Hash"]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def get_hasher(name: str) -> Callable[[], "hashlib._Hash"]:
    name_lc = name.lower()
    if name_lc not in SUPPORTED_HASHES:
        raise ValueError(
            f"Unsupported hash: {name}. Supported: {sorted(SUPPORTED_HASHES.keys())}"
        )
    return SUPPORTED_HASHES[name_lc]


def compute_hash(name: str, data: bytes) -> bytes:
    h = get_hasher(name)()
    h.update(data)
    return h.digest()
