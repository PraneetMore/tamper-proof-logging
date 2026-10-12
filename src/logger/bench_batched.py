"""
Compare per-entry commits vs batched commits for the persistent pipeline.
"""
import time
from pathlib import Path

from src.logger.chain import ChainBuilder
from src.logger.storage import Storage
from src.logger.config import DATA_DIR


def run(use_batched, n=50_000, batch_size=1_000, commit_every=10_000):
    db_path = DATA_DIR / ("bench_batched.db" if use_batched else "bench_perentry.db")
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    builder = ChainBuilder("bench", "bench")
    payload = "batched benchmark entry " * 8

    all_entries = []
    start = time.perf_counter()
    for i in range(n):
        tier, alg = "high", "sha512"
        entry = builder.build_entry(payload, tier=tier, algorithm=alg)
        all_entries.append(entry)
        if not use_batched and len(all_entries) >= batch_size:
            storage.insert_entries_batch(all_entries, device_id="bench")
            all_entries = []
    if use_batched:
        storage.insert_entries_large_batch(all_entries, device_id="bench",
                                            batch_size=commit_every)
    elif all_entries:
        storage.insert_entries_batch(all_entries, device_id="bench")
    elapsed = time.perf_counter() - start
    db_size = db_path.stat().st_size if db_path.exists() else 0
    db_path.unlink(missing_ok=True)
    for suf in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suf)
        if p.exists():
            p.unlink()
    return n / elapsed, db_size


if __name__ == "__main__":
    for label, flag in [("per-entry commits", False),
                        ("batched commits (10k)", True)]:
        tp, size = run(flag)
        print(f"{label:26} {tp:>14,.0f} logs/sec   db={size/1024/1024:.2f} MB")
