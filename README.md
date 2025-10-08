## Comparative Study of Hash Functions

A hands-on project comparing MD5, SHA-1, SHA-256, SHA-3, SHA-512, and BLAKE2. It includes:

- Benchmarking throughput and latency across input sizes
- Avalanche effect experiments and visualizations
- Birthday-attack simulator on a toy hash (for intuition only)
- Length extension demo on Merkle–Damgård hashes and HMAC countermeasure
- Password hashing demo (bcrypt, Argon2) with timing and configuration tips
- Streamlit dashboard and CLI to run experiments; Jupyter notebook for report-ready plots

### Quickstart (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run Streamlit app
streamlit run app/streamlit_app.py

# CLI examples
python -m cli bench --algorithms md5,sha1,sha256,sha3_256,blake2b --sizes 1,64,256,1024 --trials 5
python -m cli avalanche --algorithms md5,sha256,sha3_256 --msg-size 32 --trials 3
python -m cli collide --bits 22 --max-iters 200000
```

### Repository Layout

```
src/hash_bench/
  hashes.py              # Thin wrappers around hashlib implementations
  benchmark.py           # Throughput/latency benchmarks
  avalanche.py           # Avalanche effect experiments
  birthday.py            # Toy hash + collision demo
  length_extension.py    # Length extension demo + HMAC comparison
  password_hashing.py    # bcrypt and Argon2 demos
app/streamlit_app.py     # UI to run and visualize experiments
cli/__init__.py
cli/main.py              # Typer CLI entrypoint
notebooks/analysis.ipynb # Generate charts for the report
```

### Notes

- Uses Python's `hashlib` for MD5, SHA-1/256/512, SHA3, and BLAKE2.
- The birthday attack uses a toy reduced-space hash to make collisions feasible for demonstration.
- Length extension demo uses built-in simulation (no external dependencies required).
