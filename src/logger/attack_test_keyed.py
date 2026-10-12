"""
Attack matrix for the keyed chain and for the adaptive attacker.
Compares detection against the unkeyed chain for the same attack classes.
"""
import sys
from pathlib import Path

sys.path.insert(0, ".")

from src.logger.storage import Storage
from src.logger.chain import (
    leaf_hash, chain_hash, utc_now_iso, segment_digest, batch_digest,
)
from src.logger.keyed_chain import load_or_create_key, keyed_chain_hash, keyed_genesis
from src.logger.sync import SyncManager, checkpoint_digest
from src.logger.verify import verify_all_checkpoints


class KeyedChainBuilder:
    def __init__(self, device_id: str, deployment_id: str, key: bytes):
        self.device_id = device_id
        self.deployment_id = deployment_id
        self.key = key
        self.prev = keyed_genesis(key, device_id, deployment_id)
        self.index = 0

    def build_entry(self, content: str, tier: str = "high",
                    algorithm: str = "sha512",
                    event_type: str = "test", source: str = "test"):
        content_bytes = content.encode("utf-8")
        leaf = leaf_hash(algorithm, content_bytes)
        ts = utc_now_iso()
        ch = keyed_chain_hash(self.key, self.prev, self.index, ts,
                              tier, algorithm, leaf)
        entry = {
            "entry_index": self.index,
            "device_id": self.device_id,
            "timestamp": ts,
            "tier": tier,
            "algorithm": algorithm,
            "content": content,
            "leaf_hash": leaf.hex(),
            "prev_hash": self.prev.hex(),
            "chain_hash": ch.hex(),
            "event_type": event_type,
            "source": source,
        }
        self.prev = ch
        self.index += 1
        return entry


def _build_keyed(db_path, device_id="keyed-test", n=50,
                 deployment_id="keyed-deploy"):
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    key = load_or_create_key()
    b = KeyedChainBuilder(device_id, deployment_id, key)
    batch = [b.build_entry(f"entry-{i}", tier="high", algorithm="sha512",
                           event_type="test") for i in range(n)]
    storage.insert_entries_batch(batch, device_id=device_id)
    SyncManager(storage=storage).create_checkpoint(device_id)
    return storage, device_id, n, key


def _build_unkeyed(db_path, device_id="atk-test", n=50,
                   deployment_id="atk-deploy"):
    from src.logger.chain import ChainBuilder
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path=db_path)
    b = ChainBuilder(device_id, deployment_id)
    batch = [b.build_entry(f"entry-{i}", tier="high", algorithm="sha512",
                           event_type="test") for i in range(n)]
    storage.insert_entries_batch(batch, device_id=device_id)
    SyncManager(storage=storage).create_checkpoint(device_id)
    return storage, device_id, n


def _verify_keyed(storage, device_id, key):
    """Verify the keyed chain using a specific key."""
    with storage._conn() as c:
        cps = c.execute(
            "SELECT * FROM checkpoints WHERE device_id=? ORDER BY seq",
            (device_id,),
        ).fetchall()
    for cp in cps:
        rows = storage.get_entries_between(
            cp["segment_start"], cp["segment_end"], device_id
        )
        prev = bytes.fromhex(cp["chain_start"])
        for row in rows:
            leaf = leaf_hash(row["algorithm"], row["content"].encode("utf-8"))
            if leaf.hex() != row["leaf_hash"]:
                return False, "leaf mismatch"
            ch = keyed_chain_hash(key, prev, row["entry_index"],
                                  row["timestamp"], row["tier"],
                                  row["algorithm"], leaf)
            if ch.hex() != row["chain_hash"]:
                return False, "chain mismatch"
            prev = ch
    return True, "ok"


def _cp_dict_from_row(row):
    """
    Convert a SQLite checkpoint row (which uses 'seq') to a dict
    compatible with checkpoint_digest() (which uses 'sequence').
    """
    cp = dict(row)
    if "seq" in cp and "sequence" not in cp:
        cp["sequence"] = cp.pop("seq")
    return cp


def test_privileged_offline_attacker(trials=100, n=50):
    """Attacker tampers with DB but does not have the key."""
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/keyed_atk_{i}.db")
        storage, dev, _, key = _build_keyed(db, n=n)
        with storage._conn() as c:
            c.execute(
                "UPDATE entries SET content=? WHERE device_id=? AND entry_index=?",
                ("tampered", dev, n // 2),
            )
        ok, _ = _verify_keyed(storage, dev, key)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
    return detected, trials


def test_adaptive_unkeyed(trials=100, n=50):
    """
    Adaptive attacker recomputes chain AND checkpoints.
    Unkeyed chain should be defeated (0/100).
    """
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/atk_adaptive_{i}.db")
        storage, dev, _ = _build_unkeyed(db, n=n)

        with storage._conn() as c:
            rows = c.execute(
                "SELECT * FROM entries WHERE device_id=? ORDER BY entry_index",
                (dev,),
            ).fetchall()
        entries = [dict(r) for r in rows]
        entries[n // 2]["content"] = "adaptive attacker's version"

        # Recompute the whole chain
        prev = bytes.fromhex(entries[0]["prev_hash"])
        for e in entries:
            leaf = leaf_hash(e["algorithm"], e["content"].encode("utf-8"))
            ch = chain_hash(prev, e["entry_index"], e["timestamp"],
                            e["tier"], e["algorithm"], leaf)
            e["leaf_hash"] = leaf.hex()
            e["chain_hash"] = ch.hex()
            prev = ch

        with storage._conn() as c:
            for e in entries:
                c.execute(
                    "UPDATE entries SET content=?, leaf_hash=?, chain_hash=? "
                    "WHERE device_id=? AND entry_index=?",
                    (e["content"], e["leaf_hash"], e["chain_hash"],
                     dev, e["entry_index"]),
                )

        # Recompute checkpoints consistently
        with storage._conn() as c:
            cps = c.execute(
                "SELECT * FROM checkpoints WHERE device_id=? ORDER BY seq",
                (dev,),
            ).fetchall()
        cps = [_cp_dict_from_row(cp) for cp in cps]  # <-- the fix
        prev_digest = "0" * 128
        for cp in cps:
            seg_rows = [e for e in entries
                        if cp["segment_start"] <= e["entry_index"] <= cp["segment_end"]]
            cp["prev_digest"] = prev_digest
            cp["segment_digest"] = segment_digest(seg_rows)
            cp["batch_digest"] = batch_digest(seg_rows)
            cp["chain_start"] = seg_rows[0]["prev_hash"]
            cp["chain_end"] = seg_rows[-1]["chain_hash"]
            cp["checkpoint_digest"] = checkpoint_digest(cp)
            prev_digest = cp["checkpoint_digest"]

            with storage._conn() as c:
                c.execute("""
                    UPDATE checkpoints
                    SET prev_digest=?, segment_digest=?, batch_digest=?,
                        chain_start=?, chain_end=?, checkpoint_digest=?
                    WHERE device_id=? AND seq=?
                """, (
                    cp["prev_digest"], cp["segment_digest"], cp["batch_digest"],
                    cp["chain_start"], cp["chain_end"], cp["checkpoint_digest"],
                    dev, cp["sequence"],
                ))

        ok, msg = verify_all_checkpoints(storage, dev)
        if not ok:
            detected += 1
            if i < 3:
                print(f"    trial {i}: verifier rejected: {msg}")
        db.unlink(missing_ok=True)
    return detected, trials


def test_adaptive_keyed(trials=100, n=50):
    """Adaptive attacker against keyed chain. Should fail (100/100)."""
    detected = 0
    for i in range(trials):
        db = Path(f"/tmp/atk_adaptive_keyed_{i}.db")
        storage, dev, _, key = _build_keyed(db, n=n)

        with storage._conn() as c:
            rows = c.execute(
                "SELECT * FROM entries WHERE device_id=? ORDER BY entry_index",
                (dev,),
            ).fetchall()
        entries = [dict(r) for r in rows]
        entries[n // 2]["content"] = "adaptive attacker's version"

        prev = bytes.fromhex(entries[0]["prev_hash"])
        for e in entries:
            leaf = leaf_hash(e["algorithm"], e["content"].encode("utf-8"))
            ch = chain_hash(prev, e["entry_index"], e["timestamp"],
                            e["tier"], e["algorithm"], leaf)
            e["leaf_hash"] = leaf.hex()
            e["chain_hash"] = ch.hex()
            prev = ch

        with storage._conn() as c:
            for e in entries:
                c.execute(
                    "UPDATE entries SET content=?, leaf_hash=?, chain_hash=? "
                    "WHERE device_id=? AND entry_index=?",
                    (e["content"], e["leaf_hash"], e["chain_hash"],
                     dev, e["entry_index"]),
                )

        ok, _ = _verify_keyed(storage, dev, key)
        if not ok:
            detected += 1
        db.unlink(missing_ok=True)
    return detected, trials


def main():
    print("Adaptive and keyed attack matrix")
    print()

    d, n = test_privileged_offline_attacker()
    print(f"  privileged offline attacker (keyed chain)      {d:>4}/{n}")

    d, n = test_adaptive_unkeyed()
    print(f"  adaptive attacker (unkeyed chain)               {d:>4}/{n}")

    d, n = test_adaptive_keyed()
    print(f"  adaptive attacker (keyed chain)                 {d:>4}/{n}")

    print()
    print("Interpretation:")
    print("  - Keyed chain detects the privileged offline attacker.")
    print("  - Adaptive attacker defeats the unkeyed chain (0/100).")
    print("  - Keyed chain defeats the adaptive attacker (100/100).")


if __name__ == "__main__":
    main()
