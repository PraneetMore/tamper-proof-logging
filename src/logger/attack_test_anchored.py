"""
Anchored-verification attack matrix.

Each trial:
  1. builds a fresh chain in a fresh DB,
  2. snapshots checkpoint digests to an EXTERNAL reference file
     (JSON on disk, not stored in the same DB),
  3. applies the tamper,
  4. runs verify_all_checkpoints(..., trusted_reference=ref),
  5. counts detection if and only if the verifier returns False.

The external reference file represents what the remote append-only
server would hold — a source of truth outside the local DB.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

from src.logger.storage import Storage
from src.logger.chain import ChainBuilder
from src.logger.sync import SyncManager
from src.logger.verify import verify_all_checkpoints


# ─── helpers ────────────────────────────────────────────────────────

def _build(db_path, device_id="anch-test", n=50,
           deployment_id="anch-deploy", tier="high", algorithm="sha512"):
    """Build n entries and one checkpoint covering them."""
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    b = ChainBuilder(device_id, deployment_id)
    batch = [b.build_entry(f"entry-{i}", tier=tier, algorithm=algorithm)
             for i in range(n)]
    storage.insert_entries_batch(batch, device_id=device_id)
    SyncManager(storage=storage).create_checkpoint(device_id)
    return storage, device_id, n


def _snapshot_external(storage, device_id, ref_path):
    """Write {seq: digest} to a JSON file OUTSIDE the DB."""
    ref = {}
    with storage._conn() as c:
        for r in c.execute(
            "SELECT seq, checkpoint_digest FROM checkpoints WHERE device_id=?",
            (device_id,),
        ):
            ref[r["seq"]] = r["checkpoint_digest"]
    Path(ref_path).write_text(json.dumps(ref))
    return ref


def _load_external(ref_path):
    raw = json.loads(Path(ref_path).read_text())
    # JSON stringifies dict keys; convert back to int for SQLite lookups
    return {int(k): v for k, v in raw.items()}


def _verify_anchored(storage, device_id, ref_path):
    ref = _load_external(ref_path)
    return verify_all_checkpoints(storage, device_id, trusted_reference=ref)


# ─── attacks ────────────────────────────────────────────────────────

def test_modification_anchored(trials=100, n=50):
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/anch_mod_{i}.db")
        ref = f"/tmp/anch_mod_{i}.json"
        storage, dev, _ = _build(db, n=n)
        _snapshot_external(storage, dev, ref)
        with storage._conn() as c:
            c.execute(
                "UPDATE entries SET content=? WHERE device_id=? AND entry_index=?",
                ("tampered", dev, n // 2),
            )
        ok, _ = _verify_anchored(storage, dev, ref)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
        Path(ref).unlink(missing_ok=True)
    return detected, trials


def test_deletion_anchored(trials=100, n=50):
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/anch_del_{i}.db")
        ref = f"/tmp/anch_del_{i}.json"
        storage, dev, _ = _build(db, n=n)
        _snapshot_external(storage, dev, ref)
        with storage._conn() as c:
            c.execute(
                "DELETE FROM entries WHERE device_id=? AND entry_index=?",
                (dev, n // 2),
            )
        ok, _ = _verify_anchored(storage, dev, ref)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
        Path(ref).unlink(missing_ok=True)
    return detected, trials


def test_insertion_inside_anchored(trials=100, n=50):
    """
    Free an index inside the checkpointed range by deleting the real
    entry there, then insert a fabricated entry at the same index.
    Detected via chain-link mismatch at that index.
    """
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/anch_ins_{i}.db")
        ref = f"/tmp/anch_ins_{i}.json"
        storage, dev, _ = _build(db, n=n)
        _snapshot_external(storage, dev, ref)

        target = n // 2
        with storage._conn() as c:
            # free the index so the insert does not violate PK
            c.execute(
                "DELETE FROM entries WHERE device_id=? AND entry_index=?",
                (dev, target),
            )
            # insert a fabricated entry at the freed index
            c.execute(
                """INSERT INTO entries
                   (entry_index, device_id, timestamp, tier, algorithm,
                    content, leaf_hash, prev_hash, chain_hash, event_type)
                   VALUES (?, ?, ?, 'high', 'sha512', ?, 'x', 'x', 'x', 'injected')""",
                (target, dev, "2026-01-01T00:00:00Z", "injected"),
            )

        ok, _ = _verify_anchored(storage, dev, ref)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
        Path(ref).unlink(missing_ok=True)
    return detected, trials


def test_truncation_inside_anchored(trials=100, n=200):
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/anch_trunc_{i}.db")
        ref = f"/tmp/anch_trunc_{i}.json"
        storage, dev, _ = _build(db, n=n)
        _snapshot_external(storage, dev, ref)
        # Remove the last 20 entries, which are inside the checkpoint
        with storage._conn() as c:
            c.execute(
                "DELETE FROM entries WHERE device_id=? AND entry_index >= ?",
                (dev, n - 20),
            )
        ok, _ = _verify_anchored(storage, dev, ref)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
        Path(ref).unlink(missing_ok=True)
    return detected, trials


def test_post_checkpoint_insertion_anchored(trials=100, n=200):
    """Out of scope by design - expected NOT detected under any mode."""
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/anch_postcp_{i}.db")
        ref = f"/tmp/anch_postcp_{i}.json"
        storage, dev, _ = _build(db, n=n)
        _snapshot_external(storage, dev, ref)
        with storage._conn() as c:
            c.execute(
                """INSERT INTO entries
                   (entry_index, device_id, timestamp, tier, algorithm,
                    content, leaf_hash, prev_hash, chain_hash, event_type)
                   VALUES (?, ?, ?, 'high', 'sha512', ?, 'x', 'x', 'x', 'post_cp')""",
                (n + 5, dev, "2026-01-01T00:00:00Z", "post-cp"),
            )
        ok, _ = _verify_anchored(storage, dev, ref)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
        Path(ref).unlink(missing_ok=True)
    return detected, trials


# ─── runner ─────────────────────────────────────────────────────────

def main():
    print("Anchored-verification attack matrix")
    print()
    for name, fn in [
        ("modification (anchored)",          test_modification_anchored),
        ("deletion (anchored)",              test_deletion_anchored),
        ("insertion_inside (anchored)",      test_insertion_inside_anchored),
        ("truncation in-segment (anchored)", test_truncation_inside_anchored),
        ("post-cp insertion (o.o.s.)",       test_post_checkpoint_insertion_anchored),
    ]:
        d, n = fn()
        recall = d / n if n else 0.0
        print(f"  {name:38}  detected {d:>4}/{n}  recall={recall:.2%}")


if __name__ == "__main__":
    main()
