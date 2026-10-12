"""
Benchmark with 5-run confidence intervals.
"""

import statistics
import time

from .chain import ChainBuilder, leaf_hash
from .storage import Storage
from .config import DATA_DIR


def _mean_ci(values, confidence=0.95):
    n = len(values)
    if n < 2:
        return values[0], 0.0
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    t = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571}.get(n - 1, 1.96)
    return mean, t * stdev / (n ** 0.5)


def bench_leaf_hashing(iterations=100_000, runs=5):
    payload = b"x" * 256
    out = {}
    for alg in ("sha512", "blake2s"):
        throughputs = []
        latencies = []
        for _ in range(runs):
            for _ in range(1000):
                leaf_hash(alg, payload)
            start = time.perf_counter()
            for _ in range(iterations):
                leaf_hash(alg, payload)
            elapsed = time.perf_counter() - start
            throughputs.append(iterations / elapsed)
            latencies.append((elapsed / iterations) * 1_000_000)
        out[alg] = {
            "ops_per_sec_mean": statistics.mean(throughputs),
            "ops_per_sec_ci95": _mean_ci(throughputs)[1],
            "us_per_op_mean": statistics.mean(latencies),
            "us_per_op_ci95": _mean_ci(latencies)[1],
        }
    return out


def bench_chain_in_memory(n=100_000, runs=5):
    throughputs = []
    for _ in range(runs):
        b = ChainBuilder("bench", "bench")
        start = time.perf_counter()
        for _ in range(n):
            b.build_entry("benchmark entry " * 8, tier="high", algorithm="sha512")
        elapsed = time.perf_counter() - start
        throughputs.append(n / elapsed)
    return {
        "logs_per_sec_mean": statistics.mean(throughputs),
        "logs_per_sec_ci95": _mean_ci(throughputs)[1],
    }


def bench_persistent(n=50_000, batch_size=1000, runs=5):
    throughputs = []
    db_sizes = []
    for i in range(runs):
        db_path = DATA_DIR / f"bench_ci_{i}.db"
        if db_path.exists():
            db_path.unlink()
        storage = Storage(db_path=db_path)
        b = ChainBuilder("bench", "bench")
        start = time.perf_counter()
        batch = []
        for j in range(n):
            batch.append(b.build_entry("persistent bench " * 8, tier="high", algorithm="sha512"))
            if len(batch) >= batch_size:
                storage.insert_entries_batch(batch, device_id="bench")
                batch = []
        if batch:
            storage.insert_entries_batch(batch, device_id="bench")
        elapsed = time.perf_counter() - start
        throughputs.append(n / elapsed)
        db_sizes.append(db_path.stat().st_size)
        for suf in ("", "-wal", "-shm"):
            p = DATA_DIR / f"bench_ci_{i}.db{suf}"
            if p.exists():
                p.unlink()
    return {
        "logs_per_sec_mean": statistics.mean(throughputs),
        "logs_per_sec_ci95": _mean_ci(throughputs)[1],
        "db_size_bytes_mean": statistics.mean(db_sizes),
    }


def main():
    print("=" * 60)
    print("BENCHMARK WITH 95% CONFIDENCE INTERVALS (5 runs)")
    print("=" * 60)

    print("\n[1] Leaf hashing (256-byte payload, 100,000 iterations, 5 runs)")
    r1 = bench_leaf_hashing()
    for alg, d in r1.items():
        print(f"    {alg:8} : {d['ops_per_sec_mean']:>12,.0f} +/- {d['ops_per_sec_ci95']:>10,.0f} ops/sec")
        print(f"               {d['us_per_op_mean']:.3f} +/- {d['us_per_op_ci95']:.3f} us/op")

    print("\n[2] Chain in-memory (100,000 entries, 5 runs)")
    r2 = bench_chain_in_memory()
    print(f"    {r2['logs_per_sec_mean']:>12,.0f} +/- {r2['logs_per_sec_ci95']:>10,.0f} logs/sec")

    print("\n[3] Persistent pipeline (50,000 entries, batch=1000, 5 runs)")
    r3 = bench_persistent()
    print(f"    {r3['logs_per_sec_mean']:>12,.0f} +/- {r3['logs_per_sec_ci95']:>10,.0f} logs/sec")
    print(f"    DB size: {r3['db_size_bytes_mean']:,.0f} bytes")


if __name__ == "__main__":
    main()
