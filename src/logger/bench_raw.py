"""Raw SQLite baseline with 95% CI (5 runs)."""
import statistics
import sqlite3
import time
from pathlib import Path
from src.logger.config import DATA_DIR


def raw_once(n=50_000):
    db_path = DATA_DIR / "bench_raw.db"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            entry_index INTEGER PRIMARY KEY,
            device_id TEXT, timestamp TEXT, content TEXT
        )
    """)
    payload = "raw benchmark entry " * 8
    start = time.perf_counter()
    conn.execute("BEGIN TRANSACTION")
    for i in range(n):
        c.execute("INSERT INTO entries VALUES (?, ?, ?, ?)",
                  (i, "raw", "2026-01-01T00:00:00Z", payload))
    conn.commit()
    elapsed = time.perf_counter() - start
    db_size = db_path.stat().st_size
    conn.close()
    db_path.unlink()
    for suf in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suf)
        if p.exists():
            p.unlink()
    return n / elapsed, db_size


if __name__ == "__main__":
    ts, ss = [], []
    for _ in range(5):
        t, s = raw_once()
        ts.append(t)
        ss.append(s)
    mean_t = statistics.mean(ts)
    stdev_t = statistics.stdev(ts)
    ci_t = 2.776 * stdev_t / (len(ts) ** 0.5)
    db_mb = statistics.mean(ss) / 1024 / 1024
    print(f"Raw SQLite:    {mean_t:>12,.0f}  ± {ci_t:>10,.0f} logs/sec   db={db_mb:.2f} MB")
