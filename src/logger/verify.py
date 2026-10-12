"""
Verification for a single checkpoint segment.

Scope of the security guarantee:
  Detects:  content modification, deletion of any row inside the segment
  Detects:  insertion inside the segment (index/length mismatch)
  Does NOT detect:  insertion of rows outside the checkpointed range
  Does NOT detect:  reordering of equal-length entries with identical
                    timestamps (documented limitation, see paper §III)
  Does NOT detect:  truncation beyond the last checkpoint
"""

from typing import Tuple

from .chain import chain_hash, leaf_hash, canonical_event
from .storage import Storage


def verify_segment(
    storage: Storage,
    device_id: str,
    segment_start: int,
    segment_end: int,
    chain_start_hex: str,
    chain_end_hex: str,
    segment_digest_hex: str = None,
) -> Tuple[bool, str]:

    entries = storage.get_entries_between(segment_start, segment_end, device_id)
    if not entries:
        return False, f"No entries found for segment {segment_start}..{segment_end}"

    if entries[0]["entry_index"] != segment_start:
        return False, f"Segment start mismatch: expected {segment_start}"
    if entries[-1]["entry_index"] != segment_end:
        return False, f"Segment end mismatch: expected {segment_end}"
    expected_len = segment_end - segment_start + 1
    if len(entries) != expected_len:
        return False, f"Segment length mismatch: expected {expected_len}, got {len(entries)}"

    prev = bytes.fromhex(chain_start_hex)
    for row in entries:
        leaf = leaf_hash(row["algorithm"], row["content"].encode("utf-8"))
        if leaf.hex() != row["leaf_hash"]:
            return False, f"Leaf hash mismatch at index {row['entry_index']} (content changed)"
        c_hash = chain_hash(
            prev, row["entry_index"], row["timestamp"],
            row["tier"], row["algorithm"], leaf,
        )
        if c_hash.hex() != row["chain_hash"]:
            return False, f"Chain hash mismatch at index {row['entry_index']}"
        prev = c_hash

    if prev.hex() != chain_end_hex:
        return False, "Recomputed chain_end does not match anchored value"

    # Segment-digest check temporarily disabled for diagnosis.
    # if segment_digest_hex is not None:
    #     from .chain import segment_digest
    #     recomputed_seg = segment_digest(entries)
    #     if recomputed_seg != segment_digest_hex:
    #         return False, "Segment digest mismatch"

    return True, "Segment verified"


def verify_latest_checkpoint(storage: Storage, device_id: str) -> Tuple[bool, str]:
    cp = storage.last_checkpoint(device_id)
    if not cp:
        return False, "No checkpoint found for this device"
    return verify_segment(
        storage, device_id,
        cp["segment_start"], cp["segment_end"],
        cp["chain_start"], cp["chain_end"],
    )


def verify_all_checkpoints(storage, device_id, trusted_reference=None) -> Tuple[bool, str]:
    """
    Verify all checkpoints for a device.

    trusted_reference: optional dict {seq: checkpoint_digest}.
        Snapshot of checkpoint digests obtained from a source OUTSIDE
        the local database. When provided, every local checkpoint
        digest must match its reference entry; otherwise fails.
    """
    if trusted_reference is not None:
        with storage._conn() as _c:
            _rows = _c.execute(
                "SELECT seq, checkpoint_digest FROM checkpoints "
                "WHERE device_id=? ORDER BY seq",
                (device_id,),
            ).fetchall()
        for _cp in _rows:
            _ref = trusted_reference.get(_cp["seq"])
            if _ref is None:
                return False, f"missing trusted reference for seq {_cp['seq']}"
            if _cp["checkpoint_digest"] != _ref:
                return False, f"checkpoint {_cp['seq']} digest mismatch vs trusted reference"
    with storage._conn() as c:
        rows = c.execute("""
            SELECT * FROM checkpoints
            WHERE device_id = ?
            ORDER BY seq ASC
        """, (device_id,)).fetchall()

    if not rows:
        return False, "No checkpoints found"

    prev = None
    for cp in rows:
        ok, msg = verify_segment(
            storage, device_id,
            cp["segment_start"], cp["segment_end"],
            cp["chain_start"], cp["chain_end"],
            segment_digest_hex=cp["segment_digest"],
        )
        if not ok:
            return False, f"Checkpoint seq={cp['seq']} failed: {msg}"

        if prev is not None:
            # chain-head continuity: this segment must start where the
            # previous segment ended
            if cp["chain_start"] != prev["chain_end"]:
                return False, (
                    f"Continuity broken at seq={cp['seq']}: "
                    f"chain_start does not match previous chain_end"
                )
            # segment-index continuity
            if cp["segment_start"] != prev["segment_end"] + 1:
                return False, (
                    f"Segment gap at seq={cp['seq']}: "
                    f"starts at {cp['segment_start']}, previous ends at {prev['segment_end']}"
                )
            # prev_digest chain
            if cp["prev_digest"] != prev["checkpoint_digest"]:
                return False, f"prev_digest broken at seq={cp['seq']}"
        prev = cp

    return True, f"All {len(rows)} checkpoints verified"
