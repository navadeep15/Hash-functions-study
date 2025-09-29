from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

try:
    import bcrypt  # type: ignore
except Exception:  # pragma: no cover
    bcrypt = None

try:
    from argon2 import PasswordHasher  # type: ignore
except Exception:  # pragma: no cover
    PasswordHasher = None  # type: ignore


@dataclass
class PasswordHashTiming:
    scheme: str
    param: str
    hash_ms: float


def time_bcrypt(password: bytes, cost: int = 12) -> Optional[PasswordHashTiming]:
    if bcrypt is None:
        return None
    start = time.perf_counter()
    salt = bcrypt.gensalt(rounds=cost)
    _ = bcrypt.hashpw(password, salt)
    end = time.perf_counter()
    return PasswordHashTiming("bcrypt", f"cost={cost}", (end - start) * 1000.0)


def time_argon2(password: str, time_cost: int = 2, memory_cost_kib: int = 65536, parallelism: int = 2) -> Optional[PasswordHashTiming]:
    if PasswordHasher is None:
        return None
    ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost_kib, parallelism=parallelism)
    start = time.perf_counter()
    _ = ph.hash(password)
    end = time.perf_counter()
    return PasswordHashTiming("argon2", f"t={time_cost},m={memory_cost_kib}KiB,p={parallelism}", (end - start) * 1000.0)
