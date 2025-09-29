from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


@dataclass
class ToyHashSpec:
    name: str
    output_bits: int


def toy_hash_factory(output_bits: int) -> Callable[[bytes], int]:
    """
    Create a toy hash function returning an integer with `output_bits`.
    Construction: xorshift of 64-bit state with simple mixing; not secure.
    """
    mask = (1 << output_bits) - 1

    def toy_hash(data: bytes) -> int:
        state = 0x9E3779B97F4A7C15  # golden ratio constant
        for b in data:
            state ^= b + 0x9E3779B97F4A7C15 + ((state << 6) & 0xFFFFFFFFFFFFFFFF) + (state >> 2)
            # xorshift mix
            state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
            state ^= (state >> 7)
            state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
        # final fold to desired bits
        folded = (state ^ (state >> output_bits)) & mask
        return folded

    return toy_hash


def find_collision(
    output_bits: int = 24,
    max_iters: int = 2_000_000,
    seed: Optional[int] = None,
) -> Tuple[bytes, bytes, int, int]:
    """
    Attempt to find a collision for a toy hash by random sampling.
    Returns (m1, m2, h, iters) upon success; raises RuntimeError if not found.
    Expected work ~ O(2^(n/2)). For 24 bits, ~ 2^12 ≈ 4096 samples on average.
    """
    if seed is not None:
        random.seed(seed)
    hfun = toy_hash_factory(output_bits)
    seen: Dict[int, bytes] = {}
    for i in range(1, max_iters + 1):
        m = os.urandom(16)
        h = hfun(m)
        if h in seen and seen[h] != m:
            return seen[h], m, h, i
        seen[h] = m
    raise RuntimeError(f"No collision found in {max_iters} iterations for {output_bits}-bit toy hash")
