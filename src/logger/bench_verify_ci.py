import statistics
import sys
import time
from pathlib import Path
sys.path.insert(0, ".")

from src.logger.chain import ChainBuilder
from src.logger.storage import Storage
from src.logger.sync import SyncManager
from src.logger.verify import verify_segment


def measure_one(segment_len):
    db = Path(f"/tmp/bv_{segment_len}.db")
    if db.exists():
        db.unlink()
    s = Storage(db_path=db)
    b = ChainBuilder("bv", "bv-deploy")
    batch = [b.build_entry(f"e-{j}" * 8, tier="high", algorithm="sha512",
                           event_type="test") for j in range(segment_len)]
    s.insert_entries_batch(batch, device_id="bv")
    SyncManager(storage=s).create_checkpoint("bv")

    cp = s.last_checkpoint("bv")
    t0 = time.perf_counter()
    ok, _ = verify_segment(s, "bv",
                           cp["segment_start"], cp["segment_end"],
                           cp["chain_start"], cp["chain_end"])
    t1 = time.perf_counter()
    db.unlink(missing_ok=True)
    for suf in ("", "-wal", "-shm"):
        Path(str(db) + suf).unlink(missing_ok=True)
    return (t1 - t0) * 1000, ok


if __name__ == "__main__":
    print(f"{'segment':>8} {'mean_ms':>10} {'± 95% CI':>10} {'runs':>6}")
    for seg_len in [100, 500, 1000, 2000, 5000, 10000]:
        times = []
        for _ in range(5):
            t, _ = measure_one(seg_len)
            times.append(t)
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        ci = 2.776 * stdev / (5 ** 0.5)
        print(f"{seg_len:>8} {mean:>10.2f} {ci:>10.2f} {5:>6}")
