"""
Benchmark suite that measures THREE distinct things:

  1. leaf_hashing_only      — cost of hash functions alone (no chain, no DB)
  2. chain_in_memory        — hash + chain linking (no DB)
  3. persistent_pipeline    — hash + chain + SQLite (the real end-to-end path)

This is necessary because mixing these numbers is what caused the
contradictions in earlier drafts (629,554 logs/s vs 32 logs/s).
"""

import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .adaptive import tier_for
from .chain import ChainBuilder, chain_hash, leaf_hash
from .config import DATA_DIR
from .storage import Storage


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ─── 1. Leaf hashing only ─────────────────────────────────
def bench_leaf_hashing(iterations: int = 100_000) -> dict:
    """
    Pure hash function cost, no chain linking, no I/O.
    Same payload size for all algorithms.
    """
    payload = b"x" * 256
    results = {}

    for alg in ("sha512", "blake2s"):
        # warm-up
        for _ in range(1000):
            leaf_hash(alg, payload)

        start = time.perf_counter()
        for _ in range(iterations):
            leaf_hash(alg, payload)
        elapsed = time.perf_counter() - start

        results[alg] = {
            "ops_per_sec": iterations / elapsed,
            "us_per_op": (elapsed / iterations) * 1_000_000,
        }

    return results


# ─── 2. In-memory chain (hash + linking, no DB) ───────────
def bench_chain_in_memory(n: int = 100_000) -> dict:
    """Build a chain entirely in memory. No SQLite writes."""
    builder = ChainBuilder("bench-device", "bench-deployment")
    payload = "benchmark entry " * 8

    start = time.perf_counter()
    for _ in range(n):
        builder.build_entry(payload, tier="high", algorithm="sha512")
    elapsed = time.perf_counter() - start

    return {
        "entries": n,
        "elapsed_sec": elapsed,
        "logs_per_sec": n / elapsed,
    }


# ─── 3. Full persistent pipeline (hash + chain + SQLite) ──
def bench_persistent(n: int = 50_000, batch_size: int = 1000) -> dict:
    """
    Builds a real chain, writes to a temporary SQLite DB in batches.
    Reports the honest end-to-end throughput.
    """
    db_path = DATA_DIR / "bench.db"
    if db_path.exists():
        db_path.unlink()

    storage = Storage(db_path=db_path)
    builder = ChainBuilder("bench-device", "bench-deployment")
    payload = "persistent benchmark entry " * 8

    start = time.perf_counter()

    batch = []
    for i in range(n):
        entry = builder.build_entry(payload, tier="high", algorithm="sha512")
        batch.append(entry)

        if len(batch) >= batch_size:
            storage.insert_entries_batch(batch)
            batch = []

    if batch:
        storage.insert_entries_batch(batch)

    elapsed = time.perf_counter() - start
    count = storage.count_entries()
    db_size = db_path.stat().st_size

    db_path.unlink()

    return {
        "entries": n,
        "elapsed_sec": elapsed,
        "logs_per_sec": n / elapsed,
        "db_size_bytes": db_size,
        "batch_size": batch_size,
    }


# ─── 4. Per-tier breakdown on synthetic mix ───────────────
def bench_tiered(n: int = 100_000) -> dict:
    """
    Synthesize a realistic mix:
        40% HIGH, 40% MEDIUM, 20% LOW
    Report tier counts and the persistent throughput of that mix.
    """
    db_path = DATA_DIR / "bench_tiered.db"
    if db_path.exists():
        db_path.unlink()

    storage = Storage(db_path=db_path)
    builder = ChainBuilder("bench-device", "bench-deployment")

    # Simulated events with predefined tier
    samples = (
        [("auth", "Failed login from 10.0.0.1", "high", "sha512")] * 40
        + [("process", "Process created /bin/bash", "medium", "blake2s")] * 40
        + [("info", "System started", "low", "batch")] * 20
    )

    start = time.perf_counter()
    batch = []
    counts = {"high": 0, "medium": 0, "low": 0}

    for i in range(n):
        et, content, tier, alg = samples[i % len(samples)]
        counts[tier] += 1
        entry = builder.build_entry(content, tier=tier, algorithm=alg)
        batch.append(entry)
        if len(batch) >= 1000:
            storage.insert_entries_batch(batch)
            batch = []

    if batch:
        storage.insert_entries_batch(batch)

    elapsed = time.perf_counter() - start
    db_path.unlink()

    return {
        "entries": n,
        "elapsed_sec": elapsed,
        "logs_per_sec": n / elapsed,
        "tier_counts": counts,
    }


# ─── Run all ──────────────────────────────────────────────
def run_all():
    print("=" * 60)
    print("BENCHMARK SUITE")
    print("=" * 60)

    print("\n[1] Leaf hashing only (256-byte payload)")
    r1 = bench_leaf_hashing(50_000)
    for alg, d in r1.items():
        print(f"    {alg:8} : {d['ops_per_sec']:>12,.0f} ops/sec | {d['us_per_op']:.3f} us/op")

    print("\n[2] Chain in-memory (no DB)")
    r2 = bench_chain_in_memory(50_000)
    print(f"    100,000 entries in {r2['elapsed_sec']:.2f}s → {r2['logs_per_sec']:,.0f} logs/sec")

    print("\n[3] Persistent pipeline (hash + chain + SQLite)")
    r3 = bench_persistent(50_000, batch_size=1000)
    print(f"    {r3['entries']:,} entries in {r3['elapsed_sec']:.2f}s → {r3['logs_per_sec']:,.0f} logs/sec")
    print(f"    DB size: {r3['db_size_bytes']:,} bytes")

    print("\n[4] Tiered pipeline (40/40/20 HIGH/MEDIUM/LOW mix)")
    r4 = bench_tiered(50_000)
    print(f"    {r4['entries']:,} entries in {r4['elapsed_sec']:.2f}s → {r4['logs_per_sec']:,.0f} logs/sec")
    print(f"    Tier counts: {r4['tier_counts']}")

    out = DATA_DIR / f"benchmark_{_now()}.json"
    out.write_text(json.dumps({
        "leaf_hashing": r1,
        "chain_in_memory": r2,
        "persistent_pipeline": r3,
        "tiered_pipeline": r4,
    }, indent=2))

    print(f"\nResults saved: {out}")


if __name__ == "__main__":
    run_all()
