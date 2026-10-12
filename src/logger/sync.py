"""
Checkpoint creation and remote synchronization.
"""

import hashlib
import socket
from typing import Any, Dict, Optional

import requests

from .chain import segment_digest, utc_now_iso, batch_digest
from .config import SYNC_SERVER_URL, CONNECTIVITY_TIMEOUT
from .storage import Storage


def _canonical_cp(cp: Dict[str, Any]) -> bytes:
    """
    Canonical encoding of a checkpoint for digest computation.

    Matches Equation 8 in the paper:
        A_j = H512("CHECKPOINT-V1" || LP16(device_id) || U32(j) ||
                   U32(s_j) || U32(e_j) || LP16(C_{s_j-1}) ||
                   LP16(C_{e_j}) || LP16(t_j) || LP16(A_{j-1}) ||
                   LP16(D_j) || LP16(B_j))

    Hash fields are stored as hexadecimal strings in SQLite. They are
    decoded to raw bytes before entering the commitment, then
    length-prefixed with a 2-byte big-endian length.
    """
    import struct

    def lp16(b: bytes) -> bytes:
        return struct.pack(">H", len(b)) + b

    def u32(x: int) -> bytes:
        return struct.pack(">I", x)

    def hex_to_bytes(h: str) -> bytes:
        """Decode a stored hex digest string to raw bytes.
        The 128-character ASCII sentinel is treated as raw bytes."""
        try:
            return bytes.fromhex(h)
        except ValueError:
            # Not a valid hex string — encode as UTF-8
            return h.encode("utf-8")

    buf = b"CHECKPOINT-V1"
    buf += lp16(cp["device_id"].encode("utf-8"))
    buf += u32(int(cp["sequence"]))
    buf += u32(int(cp["segment_start"]))
    buf += u32(int(cp["segment_end"]))
    buf += lp16(hex_to_bytes(cp["chain_start"]))
    buf += lp16(hex_to_bytes(cp["chain_end"]))
    buf += lp16(cp["timestamp"].encode("utf-8"))
    buf += lp16(hex_to_bytes(cp["prev_digest"]))
    buf += lp16(hex_to_bytes(cp.get("segment_digest", "") or ""))
    buf += lp16(hex_to_bytes(cp.get("batch_digest", "") or ""))
    return buf


def checkpoint_digest(cp: Dict[str, Any]) -> str:
    return hashlib.sha512(_canonical_cp(cp)).hexdigest()


class SyncManager:
    def __init__(self, server_url: str = SYNC_SERVER_URL, storage: Optional[Storage] = None):
        self.server_url = server_url
        self.storage = storage or Storage()

    def is_online(self) -> bool:
        """
        Return True only if the *checkpoint server* is reachable.
        This is what matters for sync; general internet access is not enough.
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.server_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 80
            socket.create_connection((host, port), timeout=CONNECTIVITY_TIMEOUT)
            return True
        except OSError:
            return False

    def create_checkpoint(self, device_id: str) -> Optional[Dict[str, Any]]:
        last_cp = self.storage.last_checkpoint(device_id)
        last_seq = last_cp["seq"] if last_cp else 0

        first = (
            self.storage.get_entry(last_cp["segment_end"] + 1, device_id=device_id)
            if last_cp else self.storage.get_entry(0, device_id=device_id)
        )
        last = self.storage.last_entry(device_id=device_id)

        if first is None or last is None:
            return None

        entries_in_segment = self.storage.get_entries_between(
            first["entry_index"], last["entry_index"], device_id=device_id
        )

        cp = {
            "device_id": device_id,
            "sequence": last_seq + 1,
            "segment_start": first["entry_index"],
            "segment_end": last["entry_index"],
            "chain_start": first["prev_hash"],
            "chain_end": last["chain_hash"],
            "timestamp": utc_now_iso(),
            "prev_digest": last_cp["checkpoint_digest"] if last_cp else "0" * 128,
            "segment_digest": segment_digest(entries_in_segment),
            "batch_digest": batch_digest(entries_in_segment),
        }
        cp["checkpoint_digest"] = checkpoint_digest(cp)

        # Persist (both new columns are present now)
        with self.storage._conn() as c:
            c.execute("""
                INSERT INTO checkpoints
                (device_id, seq, segment_start, segment_end, chain_start,
                 chain_end, timestamp, prev_digest, checkpoint_digest,
                 segment_digest, batch_digest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cp["device_id"], cp["sequence"], cp["segment_start"], cp["segment_end"],
                cp["chain_start"], cp["chain_end"], cp["timestamp"],
                cp["prev_digest"], cp["checkpoint_digest"], cp["segment_digest"],
                cp["batch_digest"],
            ))
            c.commit()

        return cp

    def flush_pending(self, device_id: str) -> Dict[str, Any]:
        """
        Send all locally stored checkpoints that the server has not yet
        accepted. Sends in ascending sequence order to satisfy the
        server's strictly-consecutive rule.
        """
        if not self.is_online():
            return {"status": "offline", "flushed": 0}

        # Ask the server which sequences it already has
        accepted = set()
        try:
            r = requests.get(
                f"{self.server_url}/checkpoint/{device_id}", timeout=5
            )
            if r.status_code == 200:
                for cp in r.json().get("checkpoints", []):
                    accepted.add(int(cp["sequence"]))
        except requests.RequestException:
            pass

        # Send anything the server lacks, in order
        with self.storage._conn() as c:
            rows = c.execute(
                "SELECT * FROM checkpoints WHERE device_id=? ORDER BY seq ASC",
                (device_id,),
            ).fetchall()

        flushed = 0
        for row in rows:
            cp = dict(row)
            # SQLite stores the column as 'seq'; the server expects 'sequence'
            if "seq" in cp and "sequence" not in cp:
                cp["sequence"] = cp.pop("seq")
            if cp["sequence"] in accepted:
                continue
            result = self.send_checkpoint(cp)
            if result["status"] == "synced":
                flushed += 1
            elif result["status"] == "error":
                return {"status": "error", "flushed": flushed, "error": result.get("error")}

        return {"status": "synced", "flushed": flushed}

    def send_checkpoint(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_online():
            return {"status": "offline"}
        try:
            r = requests.post(
                f"{self.server_url}/checkpoint",
                json=cp,
                timeout=10,
                cert=("data/tls/client.crt", "data/tls/client.key"),
                verify=False,
            )
            r.raise_for_status()
            return {"status": "synced", "server_response": r.json()}
        except requests.RequestException as e:
            return {"status": "error", "error": str(e)}
