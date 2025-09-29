import os
import sys
# Ensure project src/ is on sys.path for imports when running via Streamlit
_proj_root = os.path.dirname(os.path.dirname(__file__))
_src = os.path.join(_proj_root, "src")
if os.path.isdir(_src) and _src not in sys.path:
    sys.path.insert(0, _src)

import pandas as pd
import streamlit as st

from hash_bench.benchmark import run_benchmarks, results_to_rows
from hash_bench.hashes import SUPPORTED_HASHES
from hash_bench.avalanche import run_avalanche
from hash_bench.birthday import find_collision
from hash_bench.length_extension import try_length_extension, true_hmac_sha256
from hash_bench.password_hashing import time_bcrypt, time_argon2

st.set_page_config(page_title="Hash Functions Study", layout="wide")
st.title("Comparative Study of Hash Functions")

bench_tab, avalanche_tab, birthday_tab, length_tab, pwd_tab = st.tabs([
    "Benchmarks",
    "Avalanche Effect",
    "Birthday Attack (Toy)",
    "Length Extension",
    "Password Hashing",
])

with bench_tab:
    st.sidebar.header("Benchmark Controls")
    algos = st.sidebar.multiselect(
        "Algorithms",
        options=list(SUPPORTED_HASHES.keys()),
        default=["md5", "sha1", "sha256", "sha3_256", "blake2b"],
    )
    exp_sizes = st.sidebar.text_input(
        "Input sizes (bytes, comma-separated)",
        value="1,64,256,1024,4096,65536,1048576",
    )
    trials = st.sidebar.slider("Trials per point", 3, 30, 7)

    sizes = [int(x.strip()) for x in exp_sizes.split(",") if x.strip().isdigit()]

    if st.sidebar.button("Run Benchmarks"):
        with st.spinner("Running benchmarks..."):
            results = run_benchmarks(algorithms=algos or None, sizes=sizes or None, trials=trials)
            df = pd.DataFrame(results_to_rows(results))
            st.subheader("Raw Results")
            st.dataframe(df)

            st.subheader("Throughput (MB/s) vs Input Size")
            chart_df = df.pivot(index="input_size_bytes", columns="algorithm", values="mb_per_s")
            st.line_chart(chart_df)
    else:
        st.info("Configure parameters on the left and click Run Benchmarks.")

with avalanche_tab:
    st.subheader("Avalanche Effect (Bit-Flip Sensitivity)")
    sel_algos = st.multiselect(
        "Algorithms",
        options=list(SUPPORTED_HASHES.keys()),
        default=["md5", "sha1", "sha256", "sha3_256", "blake2b"],
        key="av_algos",
    )
    msg_size = st.slider("Message size (bytes)", 8, 256, 32, key="av_msg")
    av_trials = st.slider("Trials", 1, 10, 3, key="av_trials")
    if st.button("Run Avalanche Experiment"):
        with st.spinner("Running avalanche experiment..."):
            rows = run_avalanche(sel_algos or SUPPORTED_HASHES.keys(), message_size_bytes=msg_size, trials=av_trials)
            df_av = pd.DataFrame(rows)
            st.dataframe(df_av)
            st.bar_chart(df_av.set_index("algorithm")["mean_avalanche_ratio"])

with birthday_tab:
    st.subheader("Birthday Attack on a Toy Hash")
    bits = st.slider("Toy hash output bits", 16, 28, 22)
    max_iters = st.number_input("Max iterations", value=200000, step=1000)
    if st.button("Find Collision"):
        with st.spinner("Searching for a collision (random sampling)..."):
            try:
                m1, m2, hv, iters = find_collision(output_bits=bits, max_iters=int(max_iters))
                st.success(f"Collision found in {iters} iterations at {bits} bits")
                st.code(m1.hex())
                st.code(m2.hex())
                st.write(f"Hash value: {hv}")
            except Exception as e:
                st.error(str(e))

with length_tab:
    st.subheader("Length Extension (MD5/SHA-1/SHA-256) vs HMAC")
    algo = st.selectbox("Algorithm", ["md5", "sha1", "sha256"])
    original = st.text_input("Original message", value="comment=10&uid=5")
    append = st.text_input("Data to append", value="&admin=true")
    secret_len = st.slider("Secret length guess (bytes)", 8, 64, 16)
    if st.button("Attempt Length Extension"):
        fake_hex = "00" * 32  # placeholder digest; in a real demo you'd use a server-provided digest
        attempt = try_length_extension(fake_hex, original.encode(), append.encode(), secret_len, algorithm=algo)
        if attempt is None:
            st.warning("hashpumpy not available or algorithm unsupported. Install hashpumpy to run this demo.")
        else:
            ext_msg, new_hex = attempt
            st.write("Extended message (latin1 shown):")
            st.code(ext_msg.decode('latin1', errors='replace'))
            st.write("New hex digest:")
            st.code(new_hex)
    st.caption("HMAC resists length extension. Use HMAC(key, message) instead of raw hash(key || message).")

with pwd_tab:
    st.subheader("Password Hashing (bcrypt, Argon2)")
    pwd = st.text_input("Password", value="correct horse battery staple")
    cost = st.slider("bcrypt cost", 8, 14, 12)
    t_cost = st.slider("Argon2 time cost", 1, 4, 2)
    m_cost = st.selectbox("Argon2 memory (KiB)", [65536, 131072, 262144], index=0)
    p = st.selectbox("Argon2 parallelism", [1, 2, 4], index=1)
    if st.button("Run Password Hash Timings"):
        rows = []
        b = time_bcrypt(pwd.encode(), cost=cost)
        if b is not None:
            rows.append({"scheme": b.scheme, "param": b.param, "hash_ms": b.hash_ms})
        else:
            st.warning("bcrypt not installed.")
        a = time_argon2(pwd, time_cost=t_cost, memory_cost_kib=int(m_cost), parallelism=int(p))
        if a is not None:
            rows.append({"scheme": a.scheme, "param": a.param, "hash_ms": a.hash_ms})
        else:
            st.warning("argon2-cffi not installed.")
        if rows:
            dfp = pd.DataFrame(rows)
            st.dataframe(dfp)
            st.bar_chart(dfp.set_index("scheme")["hash_ms"])
