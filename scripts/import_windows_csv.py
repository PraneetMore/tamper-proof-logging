"""
Import Windows Security Event Log CSV into the tamper-evident chain.

CSV format (from Get-WinEvent | Export-Csv):
    "TimeCreated","Id","LevelDisplayName","ProviderName","Message"
    "25-08-2026 21:00:09","4672","Information","Microsoft-Windows-Security-Auditing","..."
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.logger.adaptive import tier_for
from src.logger.chain import ChainBuilder, segment_digest, utc_now_iso
from src.logger.storage import Storage
from src.logger.config import WINDOWS_HIGH_RISK_EVENT_IDS


DEVICE_ID = "windows-1"
DEPLOYMENT_ID = "windows-deployment"


def parse_timestamp(raw: str) -> str:
    """Parse '25-08-2026 21:00:09' → ISO-8601 with milliseconds, ending in 'Z'."""
    # dd-mm-yyyy HH:MM:SS
    dt = datetime.strptime(raw.strip(), "%d-%m-%Y %H:%M:%S").replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_event_id(raw: str) -> int:
    """Event ID may come as a string. Strip non-digits."""
    return int("".join(c for c in raw if c.isdigit()))


def import_csv(csv_path: Path, max_events: int = None, batch_size: int = 1000):
    storage = Storage()
    start_index = storage.count_entries(DEVICE_ID)
    last_entry = storage.last_entry(DEVICE_ID)

    builder = ChainBuilder(DEVICE_ID, DEPLOYMENT_ID, start_index)
    if last_entry is not None:
        builder.prev_hash = bytes.fromhex(last_entry["chain_hash"])

    imported = 0
    skipped = 0
    batch = []
    seen_indices = 0

    with csv_path.open("r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                event_id = normalize_event_id(row.get("Id", "0"))
            except (ValueError, TypeError):
                skipped += 1
                continue

            if event_id not in WINDOWS_HIGH_RISK_EVENT_IDS:
                skipped += 1
                continue

            try:
                ts = parse_timestamp(row["TimeCreated"])
            except (ValueError, KeyError):
                skipped += 1
                continue

            provider = (row.get("ProviderName") or "Windows").strip()
            message = (row.get("Message") or "").strip().replace("\n", " ")
            event_type = f"windows_{event_id}"
            content = f"[{provider}] {message}"

            tier, alg, _ = tier_for(event_type, content)

            entry = builder.build_entry(content, tier, alg)
            # The builder uses its own timestamp; override with parsed one
            # (rebuild because we want the source timestamp, not now())
            builder.next_index -= 1
            builder.prev_hash = bytes.fromhex(entry.prev_hash_hex)

            # Build a fresh entry with the parsed timestamp
            from src.logger.chain import ChainEntry, chain_hash, leaf_hash
            content_bytes = content.encode("utf-8")
            leaf = leaf_hash(alg, content_bytes)
            c_hash = chain_hash(
                builder.prev_hash,
                builder.next_index,
                ts,
                tier,
                alg,
                leaf,
            )
            entry = ChainEntry(
                index=builder.next_index,
                timestamp=ts,
                tier=tier,
                algorithm=alg,
                content=content,
                event_type=event_type,
                leaf_hash_hex=leaf.hex(),
                prev_hash_hex=builder.prev_hash.hex(),
                chain_hash_hex=c_hash.hex(),
            )
            builder.prev_hash = c_hash
            builder.next_index += 1

            batch.append(entry)
            imported += 1
            seen_indices += 1

            if len(batch) >= batch_size:
                storage.insert_entries_batch(batch, device_id=DEVICE_ID)
                batch = []
                print(f"  imported {imported} ...")

            if max_events and imported >= max_events:
                break

    if batch:
        storage.insert_entries_batch(batch, device_id=DEVICE_ID)

    # Create a checkpoint over the imported range
    first = storage.get_entry(start_index, device_id=DEVICE_ID)
    last = storage.last_entry(DEVICE_ID)
    if first and last:
        entries_in_seg = storage.get_entries_between(
            first["entry_index"], last["entry_index"], device_id=DEVICE_ID
        )
        seg_dig = segment_digest(entries_in_seg)
        cp = {
            "device_id": DEVICE_ID,
            "segment_start": first["entry_index"],
            "segment_end": last["entry_index"],
            "chain_start": first["prev_hash"],
            "chain_end": last["chain_hash"],
            "timestamp": utc_now_iso(),
            "prev_digest": "0" * 128,
            "segment_digest": seg_dig,
        }
        # Compute checkpoint digest
        import hashlib
        cp_bytes = "\x00".join([
            cp["device_id"], "1", str(cp["segment_start"]), str(cp["segment_end"]),
            cp["chain_start"], cp["chain_end"], cp["timestamp"], cp["prev_digest"],
            cp["segment_digest"],
        ]).encode()
        cp["checkpoint_digest"] = hashlib.sha512(cp_bytes).hexdigest()
        storage.insert_checkpoint(cp)
        # Read back the assigned seq
        with storage._conn() as _c:
            _row = _c.execute(
                "SELECT seq FROM checkpoints WHERE device_id=? ORDER BY seq DESC LIMIT 1",
                (DEVICE_ID,),
            ).fetchone()
        _seq = _row["seq"] if _row else "?"
        print(f"Checkpoint created: seq={_seq} segments={cp['segment_start']}..{cp['segment_end']}")

    print(f"\nImported {imported} Windows events (skipped {skipped})")
    print(f"Total entries for {DEVICE_ID}: {storage.count_entries(DEVICE_ID)}")
    return imported


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path,
                        default=Path.home() / "Downloads/WindowsLogs/security_logs_annual.csv")
    parser.add_argument("--max", type=int, default=None,
                        help="Maximum events to import (default: all matching)")
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"CSV not found: {args.csv}")
        sys.exit(1)

    print(f"Importing from: {args.csv}")
    import_csv(args.csv, max_events=args.max)


if __name__ == "__main__":
    main()
