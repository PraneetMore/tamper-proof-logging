"""
Attack-class test.

In-scope attacks (the security claim):
  - modification
  - deletion
  - insertion inside the checkpointed segment

Out-of-scope attacks (documented limitations, see paper §III):
  - insertion outside the checkpointed segment
  - reordering of equal-length entries
  - truncation beyond the last checkpoint
"""

import sqlite3
from pathlib import Path

from src.logger.chain import ChainBuilder, utc_now_iso
from src.logger.storage import Storage
from src.logger.verify import verify_all_checkpoints


TEST_DEVICE = "test-device"
TEST_DEPLOY = "test-deploy"
N_ENTRIES = 200


def _build_test_chain(db_path: Path):
    if db_path.exists():
        db_path.unlink()
    s = Storage(db_path=db_path)
    b = ChainBuilder(TEST_DEVICE, TEST_DEPLOY)

    entries = [b.build_entry(f"event {i}", tier="high", algorithm="sha512")
               for i in range(N_ENTRIES)]
    s.insert_entries_batch(entries, device_id=TEST_DEVICE)

    first = s.get_entry(0, device_id=TEST_DEVICE)
    last = s.get_entry(N_ENTRIES - 1, device_id=TEST_DEVICE)

    with s._conn() as c:
        c.execute("""
            INSERT INTO checkpoints
            (device_id, segment_start, segment_end, chain_start,
             chain_end, timestamp, prev_digest, checkpoint_digest,
             segment_digest)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            TEST_DEVICE, 0, N_ENTRIES - 1,
            first["prev_hash"], last["chain_hash"],
            last["timestamp"], "0" * 128, "x" * 128, "",
        ))
        c.commit()
    return s, db_path


def _detect(db_path: Path) -> bool:
    s = Storage(db_path=db_path)
    ok, _ = verify_all_checkpoints(s, TEST_DEVICE)
    return not ok


def _cleanup(db: Path):
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db) + suffix)
        if p.exists():
            p.unlink()


def test_modification(trials=5000):
    d = 0
    for i in range(trials):
        _, db = _build_test_chain(Path(f"/tmp/atk_mod_{i}.db"))
        with sqlite3.connect(str(db)) as c:
            c.execute("UPDATE entries SET content='X' WHERE entry_index=50")
            c.commit()
        if _detect(db):
            d += 1
        _cleanup(db)
    return d, trials


def test_deletion(trials=5000):
    d = 0
    for i in range(trials):
        _, db = _build_test_chain(Path(f"/tmp/atk_del_{i}.db"))
        with sqlite3.connect(str(db)) as c:
            c.execute("DELETE FROM entries WHERE entry_index=50")
            c.commit()
        if _detect(db):
            d += 1
        _cleanup(db)
    return d, trials


def test_insertion_inside(trials=5000):
    d = 0
    for i in range(trials):
        _, db = _build_test_chain(Path(f"/tmp/atk_ins_in_{i}.db"))
        with sqlite3.connect(str(db)) as c:
            c.execute("""
                INSERT OR REPLACE INTO entries
                (entry_index, device_id, timestamp, tier, algorithm,
                 content, leaf_hash, prev_hash, chain_hash)
                VALUES (100, ?, ?, 'high', 'sha512',
                        'injected-inside', 'x', 'x', 'x')
            """, (TEST_DEVICE, utc_now_iso()))
            c.commit()
        if _detect(db):
            d += 1
        _cleanup(db)
    return d, trials


def test_control(trials=5000):
    fp = 0
    for i in range(trials):
        _, db = _build_test_chain(Path(f"/tmp/atk_ctrl_{i}.db"))
        if _detect(db):
            fp += 1
        _cleanup(db)
    return fp, trials




def test_checkpoint_continuity_break(trials=100, n_entries=200):
    """
    Tamper chain_start of a checkpoint. Expected: verifier rejects.

    Builds a chain with TWO checkpoints. Tampering the second checkpoint's
    chain_start triggers the continuity check. The UPDATE must be committed
    explicitly because Storage._conn() does not auto-commit on close.
    """
    from pathlib import Path as _P
    from src.logger.chain import ChainBuilder
    from src.logger.storage import Storage
    from src.logger.sync import SyncManager
    from src.logger.verify import verify_all_checkpoints

    detected = 0
    for i in range(trials):
        db = _P(f"/tmp/atk_cont_{i}.db")
        if db.exists():
            db.unlink()
        s = Storage(db_path=db)
        b = ChainBuilder("cont-test", "cont-deploy")

        # Two checkpoints: 100 entries each
        for block in range(2):
            batch = [b.build_entry(f"e{block}-{j}", tier="high",
                                    algorithm="sha512", event_type="test")
                     for j in range(100)]
            s.insert_entries_batch(batch, device_id="cont-test")
            sync = SyncManager(storage=s)
            sync.create_checkpoint("cont-test")

        # Tamper the second checkpoint's chain_start
        with s._conn() as c:
            row = c.execute(
                "SELECT seq FROM checkpoints WHERE device_id=? "
                "ORDER BY seq DESC LIMIT 1",
                ("cont-test",),
            ).fetchone()
            second_seq = row["seq"]
            c.execute(
                "UPDATE checkpoints SET chain_start=? "
                "WHERE device_id=? AND seq=?",
                ("0" * 128, "cont-test", second_seq),
            )
            c.commit()  # ← REQUIRED: Storage._conn() does not auto-commit

        ok, _ = verify_all_checkpoints(s, "cont-test")
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
    return detected, trials


def main():
    print(f"Attack-class test ({test_modification.__defaults__[0]} trials each)\n")
    for name, fn in [
        ("modification",              test_modification),
        ("deletion",                  test_deletion),
        ("insertion_inside",          test_insertion_inside),
        ("truncation (in-segment)",   test_truncation_inside_segment),
        ("post-cp insertion (o.o.s.)",test_insertion_after_checkpoint),
        ("cp continuity break",       test_checkpoint_continuity_break),
        ("low-tier batch tamper",     test_low_tier_batch_tamper),
        ("event_type tamper (o.o.s.)", test_event_type_tamper),
    ]:
        d, n = fn()
        recall = d / n if n else 0.0
        print(f"  {name:28}  detected {d:>4}/{n}  recall={recall:.2%}")

    fp, n = test_control()
    print(f"  {'control':20}  false positives {fp}/{n}  FPR={fp/n:.2%}")

    print("\nDocumented out-of-scope attacks (not tested):")
    print("  insertion outside segment")
    print("  reordering of equal-length entries")
    print("  truncation beyond last checkpoint")


def _build_checkpointed_chain(db_path: Path, n_entries: int = 200,
                              device_id: str = "atk-test"):
    """Build n_entries, create one checkpoint covering them, return storage."""
    from src.logger.chain import ChainBuilder
    from src.logger.storage import Storage
    from src.logger.sync import SyncManager

    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    builder = ChainBuilder(device_id, "atk-deploy")

    batch = []
    for i in range(n_entries):
        batch.append(builder.build_entry(f"entry-{i}", tier="high", algorithm="sha512"))
    storage.insert_entries_batch(batch, device_id=device_id)

    sync = SyncManager(storage=storage)
    sync.create_checkpoint(device_id)
    return storage, device_id, n_entries


def _verify_device(storage, device_id):
    from src.logger.verify import verify_all_checkpoints
    return verify_all_checkpoints(storage, device_id)


def test_truncation_inside_segment(trials: int = 100, n_entries: int = 200):
    """
    Remove entries inside the checkpointed segment. Expected: DETECTED
    because the segment no longer contains the number of entries the
    checkpoint claimed.
    """
    detected = 0
    for i in range(trials):
        db_path = Path(f"/tmp/atk_trunc_{i}.db")
        storage, device_id, n = _build_checkpointed_chain(db_path, n_entries)
        # Delete last 20 entries (beyond the checkpoint segment)
        with storage._conn() as c:
            c.execute(
                "DELETE FROM entries WHERE device_id=? AND entry_index >= ?",
                (device_id, n - 20),
            )
        ok, _ = _verify_device(storage, device_id)
        if not ok:
            detected += 1
        db_path.unlink(missing_ok=True)
    return detected, trials


def test_insertion_after_checkpoint(trials: int = 100, n_entries: int = 200):
    """
    Insert entries above the checkpointed segment end.
    Expected: NOT detected (documented as out-of-scope in Section III-D, item 5).
    """
    detected = 0
    for i in range(trials):
        db_path = Path(f"/tmp/atk_postcp_{i}.db")
        storage, device_id, n = _build_checkpointed_chain(db_path, n_entries)
        with storage._conn() as c:
            c.execute(
                """INSERT INTO entries
                   (entry_index, device_id, timestamp, tier, algorithm,
                    content, leaf_hash, prev_hash, chain_hash)
                   VALUES (?, ?, ?, 'high', 'sha512', ?, 'x', 'x', 'x')""",
                (n + 5, device_id, "2026-01-01T00:00:00Z", "injected-after-checkpoint"),
            )
        ok, _ = _verify_device(storage, device_id)
        if not ok:
            detected += 1
        db_path.unlink(missing_ok=True)
    return detected, trials




def test_low_tier_batch_tamper(trials=100, n_entries=300):
    """Tamper a LOW-tier entry content. Expected: verifier rejects."""
    from pathlib import Path as _P
    from src.logger.chain import ChainBuilder
    from src.logger.storage import Storage
    from src.logger.sync import SyncManager
    from src.logger.verify import verify_all_checkpoints

    detected = 0
    for i in range(trials):
        db = _P(f"/tmp/atk_low_{i}.db")
        if db.exists():
            db.unlink()
        s = Storage(db_path=db)
        b = ChainBuilder("low-test", "low-deploy")
        batch = []
        for j in range(n_entries):
            if j % 3 == 0:
                tier, alg = "high", "sha512"
            elif j % 3 == 1:
                tier, alg = "medium", "blake2s"
            else:
                tier, alg = "low", "blake2s"
            batch.append(b.build_entry(f"e-{j}", tier=tier,
                                        algorithm=alg,
                                        event_type="test"))
        s.insert_entries_batch(batch, device_id="low-test")
        SyncManager(storage=s).create_checkpoint("low-test")

        with s._conn() as c:
            c.execute(
                "UPDATE entries SET content='TAMPERED' "
                "WHERE device_id='low-test' AND tier='low' AND entry_index=("
                "SELECT MIN(entry_index) FROM entries WHERE device_id='low-test' AND tier='low')"
            )
            c.commit()

        ok, _ = verify_all_checkpoints(s, "low-test")
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
    return detected, trials




def test_event_type_tamper(trials=100, n_entries=200):
    """
    Change event_type of a committed entry without changing content.
    Expected: NOT detected (documented out-of-scope in Section III-D item 9).
    """
    from pathlib import Path as _P
    from src.logger.chain import ChainBuilder
    from src.logger.storage import Storage
    from src.logger.sync import SyncManager
    from src.logger.verify import verify_all_checkpoints

    detected = 0
    for i in range(trials):
        db = _P(f"/tmp/atk_et_{i}.db")
        if db.exists():
            db.unlink()
        s = Storage(db_path=db)
        b = ChainBuilder("et-test", "et-deploy")
        batch = [b.build_entry(f"e-{j}", tier="high", algorithm="sha512",
                                event_type="windows_4624") for j in range(n_entries)]
        s.insert_entries_batch(batch, device_id="et-test")
        SyncManager(storage=s).create_checkpoint("et-test")

        with s._conn() as c:
            c.execute(
                "UPDATE entries SET event_type='windows_4625' "
                "WHERE device_id='et-test' AND entry_index=10"
            )
            c.commit()

        ok, _ = verify_all_checkpoints(s, "et-test")
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
    return detected, trials


if __name__ == "__main__":
    main()


# ─── Out-of-scope attacks: expected to NOT be detected ──────────────





# ─── Out-of-scope attacks: expected to NOT be detected ──────────────
# These are documented as out-of-scope in Section III-D of the paper.
# We test them to confirm the boundary of the security guarantee.



