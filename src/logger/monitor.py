"""
Continuous collection loop. Collects, scores, chains, stores, and checkpoints.
Prints per-event details and continuous online/offline status.
"""

import time

from .adaptive import tier_for
from .chain import ChainBuilder
from .collector import Collector
from .config import (
    CHECKPOINT_EVERY_N_ENTRIES,
    CHECKPOINT_EVERY_SECONDS,
)
from .storage import Storage
from .sync import SyncManager


class Monitor:
    def __init__(self, device_id: str, deployment_id: str,
                 interval: int = 60, verbose: bool = True):
        self.device_id = device_id
        self.deployment_id = deployment_id
        self.interval = interval
        self.verbose = verbose
        self.collector = Collector()
        self.storage = Storage()
        self.sync = SyncManager(storage=self.storage)

    def _should_checkpoint(self) -> bool:
        last_cp = self.storage.last_checkpoint(self.device_id)
        total = self.storage.count_entries(self.device_id)
        if last_cp is None:
            return total > 0
        return (total - last_cp["segment_end"]) >= CHECKPOINT_EVERY_N_ENTRIES

    def _maybe_checkpoint(self):
        if not self._should_checkpoint():
            return
        cp = self.sync.create_checkpoint(self.device_id)
        if cp:
            result = self.sync.send_checkpoint(cp)
            status_icon = {"synced": "✅", "offline": "📡", "error": "❌"}.get(
                result["status"], "?"
            )
            print(f"[checkpoint] {status_icon} seq={cp['sequence']} "
                  f"segments={cp['segment_start']}..{cp['segment_end']} "
                  f"sync={result['status']}")

    def _network_status_line(self) -> str:
        online = self.sync.is_online()
        last_cp = self.storage.last_checkpoint(self.device_id)
        pending = 0
        if last_cp:
            # count checkpoints after the last synced one
            with self.storage._conn() as c:
                pending = c.execute("""
                    SELECT COUNT(*) FROM checkpoints WHERE device_id = ?
                """, (self.device_id,)).fetchone()[0]
        icon = "🟢 ONLINE " if online else "🔴 OFFLINE"
        return f"    {icon}  pending_checkpoints={pending}"

    def run_once(self, minutes_back: int = 2):
        events = self.collector.collect(minutes_back)
        if not events:
            print(f"[monitor] no new events  |  {self._network_status_line().strip()}")
            return 0

        start_index = self.storage.count_entries(self.device_id)
        last_entry = self.storage.last_entry(self.device_id)

        builder = ChainBuilder(self.device_id, self.deployment_id, start_index)
        if last_entry is not None:
            builder.prev_hash = bytes.fromhex(last_entry["chain_hash"])

        new_entries = []
        for ev in events:
            tier, alg, score = tier_for(ev["event_type"], ev["content"])
            entry = builder.build_entry(ev["content"], tier, alg)
            new_entries.append(entry)

            if self.verbose:
                ts = ev.get("timestamp", entry.timestamp)
                et = ev.get("event_type", "?")
                preview = ev["content"][:60].replace("\n", " ")
                print(f"  + [{ts}] {et:20} score={score:3} tier={tier:6} "
                      f"alg={alg:8} | {preview}")

        self.storage.insert_entries_batch(new_entries, device_id=self.device_id)
        print(f"[monitor] stored {len(new_entries)} entries "
              f"(total={start_index + len(new_entries)})")
        self._maybe_checkpoint()
        print(self._network_status_line())
        return len(new_entries)

    def run_forever(self):
        print(f"[monitor] starting for {self.device_id}")
        try:
            while True:
                self.run_once()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[monitor] stopped")


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--device", default="dev-1")
    parser.add_argument("--deployment", default="dep-1")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--once", action="store_true",
                        help="Run one cycle and exit")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-event output")
    args = parser.parse_args()

    m = Monitor(device_id=args.device,
                deployment_id=args.deployment,
                interval=args.interval,
                verbose=not args.quiet)

    if args.once:
        m.run_once(minutes_back=180)
    else:
        m.run_forever()


if __name__ == "__main__":
    main()
