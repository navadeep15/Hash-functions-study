from __future__ import annotations

import os
import time
from dataclasses import dataclass
from statistics import mean
from typing import Iterable, List, Dict

from .hashes import SUPPORTED_HASHES, compute_hash


@dataclass
class BenchmarkResult:
    algorithm: str
    input_size_bytes: int
    trials: int
    avg_ms: float
    min_ms: float
    max_ms: float
    mb_per_s: float


def _time_once(algorithm: str, payload: bytes) -> float:
    start = time.perf_counter()
    _ = compute_hash(algorithm, payload)
    end = time.perf_counter()
    return (end - start) * 1000.0


def run_benchmarks(
    algorithms: Iterable[str] | None = None,
    sizes: Iterable[int] | None = None,
    trials: int = 10,
) -> List[BenchmarkResult]:
    if algorithms is None:
        algorithms = list(SUPPORTED_HASHES.keys())
    if sizes is None:
        sizes = [2**k for k in range(0, 21)]  # 1B .. 1MB

    results: List[BenchmarkResult] = []
    for size in sizes:
        payload = os.urandom(size)
        for algo in algorithms:
            samples_ms: List[float] = []
            for _ in range(trials):
                samples_ms.append(_time_once(algo, payload))
            avg_ms = mean(samples_ms)
            min_ms = min(samples_ms)
            max_ms = max(samples_ms)
            mbps = (size / (1024 * 1024)) / (avg_ms / 1000.0) if avg_ms > 0 else float("inf")
            results.append(
                BenchmarkResult(
                    algorithm=algo,
                    input_size_bytes=size,
                    trials=trials,
                    avg_ms=avg_ms,
                    min_ms=min_ms,
                    max_ms=max_ms,
                    mb_per_s=mbps,
                )
            )
    return results


def results_to_rows(results: List[BenchmarkResult]) -> List[Dict[str, float]]:
    rows: List[Dict[str, float]] = []
    for r in results:
        rows.append(
            {
                "algorithm": r.algorithm,
                "input_size_bytes": r.input_size_bytes,
                "trials": r.trials,
                "avg_ms": round(r.avg_ms, 6),
                "min_ms": round(r.min_ms, 6),
                "max_ms": round(r.max_ms, 6),
                "mb_per_s": round(r.mb_per_s, 6),
            }
        )
    return rows
