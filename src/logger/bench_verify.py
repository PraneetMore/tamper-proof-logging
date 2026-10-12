"""Measure verification time vs segment length."""
import sqlite3
import time
from pathlib import Path
from src.logger.chain import ChainBuilder, segment_digest, utc_now_iso
from src.logger.storage import Storage
from src.logger.verify import verify_all_checkpoints


def build_chain(db_path: Path, n: int):
    if db_path.exists():
        db_path.unlink()
    s = Storage(db_path=db_path)
    b = ChainBuilder("bench-dev", "bench-dep")
    entries = [b.build_entry(f"event {i}", tier="high", algorithm="sha512")
               for i in range(n)]
    s.insert_entries_batch(entries, device_id="bench-dev")

    first = s.get_entry(0, device_id="bench-dev")
    last = s.get_entry(n - 1, device_id="bench-dev")
    entries_in_seg = s.get_entries_between(0, n - 1, device_id="bench-dev")
    seg = segment_digest(entries_in_seg)

    with s._conn() as c:
        c.execute("""
            INSERT INTO checkpoints
            (device_id, segment_start, segment_end, chain_start,
             chain_end, timestamp, prev_digest, checkpoint_digest,
             segment_digest)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("bench-dev", 0, n - 1,
              first["prev_hash"], last["chain_hash"],
              last["timestamp"], "0"*128, "x"*128, seg))
        c.commit()
    return s, db_path


print(f"{'segment length':>15}  {'time (ms)':>12}")
for n in [100, 500, 1000, 2000, 5000, 10000]:
    s, db = build_chain(Path(f"/tmp/bench_verify_{n}.db"), n)
    t0 = time.perf_counter()
    ok, _ = verify_all_checkpoints(s, "bench-dev")
    t1 = time.perf_counter()
    print(f"{n:>15}  {(t1-t0)*1000:>12.2f}")
    for suf in ("", "-wal", "-shm"):
        p = Path(str(db) + suf)
        if p.exists(): p.unlink()
