from __future__ import annotations

import os
from typing import Dict, Iterable, List

from .hashes import compute_hash


def _flip_bit(data: bytes, bit_index: int) -> bytes:
    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8
    if byte_index >= len(data):
        raise IndexError("bit_index out of range")
    mask = 1 << bit_in_byte
    barray = bytearray(data)
    barray[byte_index] ^= mask
    return bytes(barray)


def _hamming_distance(a: bytes, b: bytes) -> int:
    dist = 0
    for x, y in zip(a, b):
        z = x ^ y
        dist += z.bit_count()
    return dist


def avalanche_ratio_for_message(algorithm: str, message: bytes) -> float:
    """
    Compute the average avalanche ratio for a single message by flipping each bit once.
    Returns the fraction of digest bits that change on average across all flips (0..1).
    """
    base = compute_hash(algorithm, message)
    digest_bits = len(base) * 8
    total_changed_bits = 0
    flips = len(message) * 8
    if flips == 0:
        return 0.0
    for bit in range(flips):
        flipped_msg = _flip_bit(message, bit)
        d = compute_hash(algorithm, flipped_msg)
        total_changed_bits += _hamming_distance(base, d)
    avg_changed_bits = total_changed_bits / flips
    return avg_changed_bits / digest_bits


def run_avalanche(
    algorithms: Iterable[str],
    message_size_bytes: int = 32,
    trials: int = 3,
) -> List[Dict[str, float]]:
    """
    For each algorithm, sample `trials` random messages of length `message_size_bytes` and
    compute the mean avalanche ratio. Returns rows suitable for tabular display.
    """
    rows: List[Dict[str, float]] = []
    for algo in algorithms:
        samples: List[float] = []
        for _ in range(trials):
            msg = os.urandom(message_size_bytes)
            samples.append(avalanche_ratio_for_message(algo, msg))
        mean_ratio = sum(samples) / len(samples) if samples else 0.0
        rows.append(
            {
                "algorithm": algo,
                "message_size_bytes": message_size_bytes,
                "trials": trials,
                "mean_avalanche_ratio": mean_ratio,
                "expected_randomized_target": 0.5,
            }
        )
    return rows
