"""
Baseline comparison: uniform SHA-512, uniform BLAKE2s, adaptive tiering,
keyed HMAC-SHA-512 chain, and Merkle-tree log.
5 runs per configuration with 95% CI.
"""
import hashlib
import hmac
import statistics
import time
from pathlib import Path

from src.logger.chain import (
    ChainBuilder, leaf_hash, U64, LP16, B, TIER_CODES, ALG_CODES,
)
from src.logger.keyed_chain import load_or_create_key
from src.logger.merkle_log import MerkleLog
from src.logger.storage import Storage
from src.logger.config import DATA_DIR


def _run_once(mode, n=50_000, batch_size=1_000):
    db_path = DATA_DIR / f"bench_baseline_{mode}.db"
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    builder = ChainBuilder("bench", "bench")
    payload = "baseline benchmark entry " * 8

    key = load_or_create_key() if mode == "keyed" else None
    merkle = MerkleLog() if mode == "merkle" else None

    batch = []
    start = time.perf_counter()
    for i in range(n):
        if mode in ("sha512", "keyed"):
            tier, alg = "high", "sha512"
        elif mode == "blake2s":
            tier, alg = "medium", "blake2s"
        elif mode == "adaptive":
            pos = i % 10
            if pos < 4:
                tier, alg = "high", "sha512"
            elif pos < 8:
                tier, alg = "medium", "blake2s"
            else:
                tier, alg = "low", "blake2s"
        elif mode == "merkle":
            merkle.append(payload.encode("utf-8"))
            continue
        else:
            raise ValueError(mode)

        entry = builder.build_entry(payload, tier=tier, algorithm=alg,
                                     event_type="bench")
        if mode == "keyed":
            # Recompute the chain hash with HMAC
            leaf = bytes.fromhex(entry.leaf_hash_hex)
            prev = bytes.fromhex(entry.prev_hash_hex)
            msg = (prev
                   + U64(entry.index)
                   + LP16(entry.timestamp.encode("utf-8"))
                   + B(TIER_CODES[entry.tier])
                   + B(ALG_CODES[entry.algorithm])
                   + LP16(leaf))
            new_chain = hmac.new(key, msg, hashlib.sha512).digest()
            entry.chain_hash_hex = new_chain.hex()
            builder.prev_hash = new_chain
        batch.append(entry)
        if len(batch) >= batch_size:
            storage.insert_entries_batch(batch, device_id="bench")
            batch = []
    if batch:
        storage.insert_entries_batch(batch, device_id="bench")
    if merkle is not None:
        _ = merkle.root()
    elapsed = time.perf_counter() - start
    db_size = db_path.stat().st_size if db_path.exists() else 0
    db_path.unlink(missing_ok=True)
    for suf in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suf)
        if p.exists():
            p.unlink()
    return n / elapsed, db_size


def _run(mode, n=50_000, runs=5):
    ts, ss = [], []
    for _ in range(runs):
        t, s = _run_once(mode, n=n)
        ts.append(t)
        ss.append(s)
    mean_t = statistics.mean(ts)
    stdev_t = statistics.stdev(ts) if len(ts) > 1 else 0
    ci_t = 2.776 * stdev_t / (len(ts) ** 0.5)
    return {"mode": mode, "mean": mean_t, "ci": ci_t,
            "db_mb": statistics.mean(ss) / 1024 / 1024}


if __name__ == "__main__":
    print(f"{'mode':12} {'logs/sec':>12} {'+- 95% CI':>12} {'db size (MB)':>14}")
    for mode in ("sha512", "blake2s", "adaptive", "keyed", "merkle"):
        r = _run(mode)
        print(f"{r['mode']:12} {r['mean']:>12,.0f} {r['ci']:>12,.0f} {r['db_mb']:>14.2f}")
