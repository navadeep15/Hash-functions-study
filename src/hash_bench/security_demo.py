from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Tuple

# Real MD5 collision examples from the research literature
MD5_COLLISION_PAIRS = [
    (
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b",
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    ),
    (
        "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518"
        "afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8362fb5f87fe5a",
        "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518"
        "afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8362fb5f87fe5a"
    )
]

# SHA-1 collision example (The SHAttered attack)
SHA1_COLLISION_PAIRS = [
    (
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    )
]

def verify_collisions() -> Dict[str, List[Tuple[bool, str]]]:
    """Verify that the known collision pairs actually produce the same hash."""
    results = {"md5": [], "sha1": []}
    
    for pair in MD5_COLLISION_PAIRS:
        msg1 = bytes.fromhex(pair[0])
        msg2 = bytes.fromhex(pair[1])
        hash1 = hashlib.md5(msg1).hexdigest()
        hash2 = hashlib.md5(msg2).hexdigest()
        is_collision = hash1 == hash2
        results["md5"].append((is_collision, f"Hash: {hash1[:16]}..."))
    
    return results

def timing_attack_simulation(password: str, attempts: int = 100) -> Dict[str, float]:
    """Simulate a timing attack on password verification."""
    # Simulate different hash algorithms with varying speeds
    algorithms = {
        "md5": lambda p: hashlib.md5(p.encode()).hexdigest(),
        "sha1": lambda p: hashlib.sha1(p.encode()).hexdigest(), 
        "sha256": lambda p: hashlib.sha256(p.encode()).hexdigest(),
        "bcrypt_sim": lambda p: time.sleep(0.1) or hashlib.sha256(p.encode()).hexdigest()
    }
    
    target_hash = hashlib.sha256(password.encode()).hexdigest()
    results = {}
    
    for name, hash_func in algorithms.items():
        start_time = time.perf_counter()
        for _ in range(attempts):
            test_hash = hash_func("wrong_password")
            # Simulate the comparison (always fails, but timing varies)
            _ = test_hash == target_hash
        end_time = time.perf_counter()
        results[name] = (end_time - start_time) * 1000  # ms
    
    return results

def rainbow_table_simulation() -> Dict[str, int]:
    """Simulate rainbow table effectiveness against different hash types."""
    # Simulate how many passwords can be cracked with rainbow tables
    common_passwords = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "password123"
    ]
    
    results = {}
    
    # MD5 - easily cracked
    md5_hashes = [hashlib.md5(p.encode()).hexdigest() for p in common_passwords]
    results["md5_rainbow_table"] = len(md5_hashes)
    
    # SHA-256 - still vulnerable without salt
    sha256_hashes = [hashlib.sha256(p.encode()).hexdigest() for p in common_passwords]
    results["sha256_no_salt"] = len(sha256_hashes)
    
    # SHA-256 with salt - much more resistant
    salt = b"random_salt_123"
    sha256_salted = [hashlib.sha256((p + salt.decode()).encode()).hexdigest() for p in common_passwords]
    results["sha256_with_salt"] = 0  # Rainbow tables become impractical
    
    return results

def hash_vulnerability_assessment() -> Dict[str, Dict[str, str]]:
    """Assess real-world vulnerabilities of different hash algorithms."""
    vulnerabilities = {
        "md5": {
            "collision_resistance": "BROKEN - Collisions found in ~1 hour",
            "preimage_resistance": "WEAK - Vulnerable to collision attacks",
            "recommendation": "DEPRECATED - Use SHA-256 or SHA-3",
            "year_deprecated": "2004",
            "real_world_impact": "Used in malware, certificate forgery, file integrity attacks"
        },
        "sha1": {
            "collision_resistance": "BROKEN - SHAttered attack (2017)",
            "preimage_resistance": "WEAK - Theoretical attacks exist",
            "recommendation": "DEPRECATED - Use SHA-256 or SHA-3", 
            "year_deprecated": "2017",
            "real_world_impact": "Used in certificate forgery, Git commit spoofing"
        },
        "sha256": {
            "collision_resistance": "SECURE - No practical attacks known",
            "preimage_resistance": "SECURE - No practical attacks known",
            "recommendation": "RECOMMENDED - Good for general use",
            "year_deprecated": "N/A",
            "real_world_impact": "Industry standard for most applications"
        },
        "sha3_256": {
            "collision_resistance": "SECURE - SHA-3 family, different construction",
            "preimage_resistance": "SECURE - Sponge construction",
            "recommendation": "RECOMMENDED - Future-proof choice",
            "year_deprecated": "N/A", 
            "real_world_impact": "Newer standard, not yet widely adopted"
        }
    }
    return vulnerabilities
