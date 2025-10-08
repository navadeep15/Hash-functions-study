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
from hash_bench.length_extension import try_length_extension, true_hmac_sha256, simulate_length_extension_verification
from hash_bench.password_hashing import time_bcrypt, time_argon2
from hash_bench.security_demo import verify_collisions, timing_attack_simulation, rainbow_table_simulation, hash_vulnerability_assessment

st.set_page_config(page_title="Hash Functions Study", layout="wide")
st.title("Comparative Study of Hash Functions")

bench_tab, avalanche_tab, birthday_tab, length_tab, pwd_tab, security_tab = st.tabs([
    "Benchmarks",
    "Avalanche Effect", 
    "Birthday Attack (Toy)",
    "Length Extension",
    "Password Hashing",
    "Security Analysis",
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
    algo = st.selectbox("Algorithm", ["md5", "sha1", "sha256"])  # demo set
    original = st.text_input("Original message", value="comment=10&uid=5")
    append = st.text_input("Data to append", value="&admin=true")
    secret_len = st.slider("Secret length guess (bytes)", 8, 64, 16)
    if st.button("Attempt Length Extension"):
        fake_hex = "00" * 32  # placeholder
        attempt = try_length_extension(fake_hex, original.encode(), append.encode(), secret_len, algorithm=algo)
        if attempt is None:
            st.warning("Falling back to simulation (no external libs).")
            secret_key = os.urandom(16)
            attacker_msg, server_hex, extended_hex = simulate_length_extension_verification(
                original.encode(), append.encode(), secret_key, algorithm=algo, secret_length_guess=secret_len
            )
            st.write("Attacker sends:")
            st.code(attacker_msg.decode('latin1', errors='replace'))
            st.write("Server H(secret||original):")
            st.code(server_hex)
            st.write("Server H(secret||(original||pad||append)):")
            st.code(extended_hex)
            st.caption("Length extension lets an attacker forge a longer message's hash if they know the original hash and can guess secret length. HMAC prevents this.")
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

with security_tab:
    st.subheader("Real-World Security Analysis")
    
    # Vulnerability Assessment
    st.write("### Hash Algorithm Security Assessment")
    vulnerabilities = hash_vulnerability_assessment()
    
    for algo, info in vulnerabilities.items():
        with st.expander(f"{algo.upper()} Security Analysis"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Collision Resistance:** {info['collision_resistance']}")
                st.write(f"**Preimage Resistance:** {info['preimage_resistance']}")
                st.write(f"**Year Deprecated:** {info['year_deprecated']}")
            with col2:
                st.write(f"**Recommendation:** {info['recommendation']}")
                st.write(f"**Real-World Impact:** {info['real_world_impact']}")
    
    # Real Collision Verification
    st.write("### Known Collision Verification")
    if st.button("Verify Real MD5 Collisions"):
        with st.spinner("Verifying known collision pairs..."):
            collision_results = verify_collisions()
            for algo, results in collision_results.items():
                st.write(f"**{algo.upper()} Collisions:**")
                for i, (is_collision, hash_info) in enumerate(results):
                    status = "✅ CONFIRMED" if is_collision else "❌ FAILED"
                    st.write(f"Pair {i+1}: {status} - {hash_info}")
    
    # Timing Attack Simulation
    st.write("### Timing Attack Simulation")
    st.write("This demonstrates how different hash algorithms can leak information through timing differences.")
    test_password = st.text_input("Test Password", value="secret123", key="timing_pwd")
    attempts = st.slider("Number of attempts", 10, 1000, 100, key="timing_attempts")
    
    if st.button("Run Timing Attack Simulation"):
        with st.spinner("Running timing attack simulation..."):
            timing_results = timing_attack_simulation(test_password, attempts)
            df_timing = pd.DataFrame(list(timing_results.items()), columns=["Algorithm", "Time (ms)"])
            st.dataframe(df_timing)
            st.bar_chart(df_timing.set_index("Algorithm"))
            st.caption("Higher times indicate more secure algorithms (harder to time)")
    
    # Rainbow Table Simulation
    st.write("### Rainbow Table Resistance")
    if st.button("Analyze Rainbow Table Vulnerability"):
        with st.spinner("Analyzing rainbow table effectiveness..."):
            rainbow_results = rainbow_table_simulation()
            df_rainbow = pd.DataFrame(list(rainbow_results.items()), columns=["Hash Type", "Crackable Passwords"])
            st.dataframe(df_rainbow)
            st.bar_chart(df_rainbow.set_index("Hash Type"))
            st.caption("Lower numbers = more secure against rainbow table attacks")
    
    # Security Recommendations
    st.write("### Security Recommendations")
    st.info("""
    **For Different Use Cases:**
    
    - **File Integrity:** SHA-256 or SHA-3 (never MD5/SHA-1)
    - **Password Hashing:** bcrypt, Argon2, or scrypt (never raw SHA-256)
    - **Digital Signatures:** SHA-256 or SHA-3 with proper key management
    - **HMAC:** SHA-256 or SHA-3 (resists length extension attacks)
    
    **Key Takeaways:**
    - MD5 and SHA-1 are completely broken and should never be used
    - Always use salt with password hashing
    - Consider timing attack resistance for authentication systems
    - Rainbow tables make unsalted hashes vulnerable even if the hash itself is secure
    """)
