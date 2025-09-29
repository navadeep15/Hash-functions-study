import csv
from pathlib import Path

import typer

from hash_bench.benchmark import run_benchmarks, results_to_rows
from hash_bench.hashes import SUPPORTED_HASHES
from hash_bench.avalanche import run_avalanche
from hash_bench.birthday import find_collision

app = typer.Typer(help="CLI for Comparative Study of Hash Functions")


@app.command()
def bench(
    algorithms: str = typer.Option(
        "md5,sha1,sha256,sha3_256,blake2b",
        help="Comma-separated list of algorithms",
    ),
    sizes: str = typer.Option(
        "1,64,256,1024,4096,65536,1048576",
        help="Comma-separated input sizes in bytes",
    ),
    trials: int = typer.Option(7, help="Trials per data point"),
    out_csv: Path = typer.Option(Path("results/bench.csv"), help="Output CSV path"),
):
    algos = [a.strip() for a in algorithms.split(",") if a.strip()]
    sz = [int(s.strip()) for s in sizes.split(",") if s.strip()]
    results = run_benchmarks(algorithms=algos, sizes=sz, trials=trials)
    rows = results_to_rows(results)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "algorithm",
        "input_size_bytes",
        "trials",
        "avg_ms",
        "min_ms",
        "max_ms",
        "mb_per_s",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    typer.echo(f"Wrote {len(rows)} rows to {out_csv}")


@app.command()
def avalanche(
    algorithms: str = typer.Option("md5,sha1,sha256,sha3_256,blake2b"),
    msg_size: int = typer.Option(32, help="Message size in bytes"),
    trials: int = typer.Option(3, help="Trials per algorithm"),
    out_csv: Path = typer.Option(Path("results/avalanche.csv"), help="Output CSV path"),
):
    algos = [a.strip() for a in algorithms.split(",") if a.strip()]
    rows = run_avalanche(algos, message_size_bytes=msg_size, trials=trials)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["algorithm", "message_size_bytes", "trials", "mean_avalanche_ratio", "expected_randomized_target"]
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    typer.echo(f"Wrote {len(rows)} rows to {out_csv}")


@app.command()
def collide(
    bits: int = typer.Option(22, help="Toy hash output bits (16-28)"),
    max_iters: int = typer.Option(200000, help="Max iterations"),
):
    m1, m2, hv, iters = find_collision(output_bits=bits, max_iters=max_iters)
    typer.echo(f"Collision after {iters} iterations at {bits} bits. Hash value: {hv}")
    typer.echo(f"m1={m1.hex()}\nm2={m2.hex()}")


if __name__ == "__main__":
    app()
