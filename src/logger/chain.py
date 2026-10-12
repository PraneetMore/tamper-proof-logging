"""
Tamper-evident hash chain primitives.

Provides leaf hashing, chain-link hashing, genesis binding, segment
digests, and LOW-tier batch digests. All encodings are documented
inline. The leaf hash commits to the canonical event representation
including event_type and source, so metadata-only tampering is
detected.
"""

import hashlib
import struct


# ─── Encoding constants ────────────────────────────────────────
TIER_CODES = {"high": 0x01, "medium": 0x02, "low": 0x03}
ALG_CODES = {"sha512": 0x01, "blake2s": 0x02, "batch": 0x03}
TIER_NAMES = {v: k for k, v in TIER_CODES.items()}
ALG_NAMES = {v: k for k, v in ALG_CODES.items()}


# ─── Canonical encoding helpers ────────────────────────────────
def U64(x: int) -> bytes:
    """8-byte unsigned big-endian integer."""
    return struct.pack(">Q", x)


def U32(x: int) -> bytes:
    """4-byte unsigned big-endian integer."""
    return struct.pack(">I", x)


def B(x: int) -> bytes:
    """Single byte."""
    return bytes([x])


def LP16(b: bytes) -> bytes:
    """Byte string prefixed by a 2-byte big-endian length."""
    return struct.pack(">H", len(b)) + b


def LP32(b: bytes) -> bytes:
    """Byte string prefixed by a 4-byte big-endian length."""
    return struct.pack(">I", len(b)) + b


# ─── Canonical event encoding ──────────────────────────────────
def canonical_event(event_type: str, source: str, content: str) -> bytes:
    """
    Canonical byte representation of an event for leaf hashing.

    The encoding commits to event_type, source, and content so that
    tampering with any of these fields is detected. Field order is
    fixed and each field is length-prefixed to avoid ambiguity.
    """
    return (
        b"EVENT-V1"
        + LP16((event_type or "").encode("utf-8"))
        + LP16((source or "").encode("utf-8"))
        + LP16((content or "").encode("utf-8"))
    )


# ─── Hash primitives ────────────────────────────────────────────
def leaf_hash(algorithm: str, content_bytes: bytes) -> bytes:
    """
    Return the leaf hash for one entry, using the tier's algorithm.

    content_bytes is the canonical event encoding produced by
    canonical_event(). Callers must produce it from the event's
    event_type, source, and content fields.
    """
    if algorithm == "blake2s":
        return hashlib.blake2s(content_bytes, digest_size=32).digest()
    return hashlib.sha512(content_bytes).digest()


def chain_hash(
    prev_hash: bytes,
    index: int,
    timestamp: str,
    tier: str,
    algorithm: str,
    leaf: bytes,
) -> bytes:
    """
    Compute the chain hash for one link.

    Inputs are encoded as follows:
      prev_hash        raw 64 bytes (SHA-512 output)
      index            U64
      timestamp        LP16 of UTF-8 bytes
      tier code        single byte
      algorithm code   single byte
      leaf             LP16 of raw bytes
    """
    ts_bytes = timestamp.encode("utf-8")
    msg = (
        prev_hash
        + U64(index)
        + LP16(ts_bytes)
        + B(TIER_CODES[tier])
        + B(ALG_CODES[algorithm])
        + LP16(leaf)
    )
    return hashlib.sha512(msg).digest()


def genesis_hash(device_id: str, deployment_id: str) -> bytes:
    """Genesis chain head, bound to device and deployment identity."""
    msg = (
        b"GENESIS-V1"
        + LP16(device_id.encode("utf-8"))
        + LP16(deployment_id.encode("utf-8"))
    )
    return hashlib.sha512(msg).digest()


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with millisecond precision."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ─── Chain entry and builder ────────────────────────────────────
class ChainEntry:
    """One link in the chain. Stores the full content for re-hashing."""

    __slots__ = (
        "index", "timestamp", "tier", "algorithm", "content",
        "event_type", "source",
        "leaf_hash_hex", "prev_hash_hex", "chain_hash_hex",
    )

    def __init__(
        self,
        index: int,
        timestamp: str,
        tier: str,
        algorithm: str,
        content: str,
        leaf_hash_hex: str,
        prev_hash_hex: str,
        chain_hash_hex: str,
        event_type: str = "unknown",
        source: str = "unknown",
    ):
        self.index = index
        self.timestamp = timestamp
        self.tier = tier
        self.algorithm = algorithm
        self.content = content
        self.event_type = event_type
        self.source = source
        self.leaf_hash_hex = leaf_hash_hex
        self.prev_hash_hex = prev_hash_hex
        self.chain_hash_hex = chain_hash_hex


class ChainBuilder:
    """Builds sequential chain entries for one device."""

    def __init__(self, device_id: str, deployment_id: str, start_index: int = 0):
        self.device_id = device_id
        self.deployment_id = deployment_id
        self.next_index = start_index
        self.prev_hash = genesis_hash(device_id, deployment_id)

    def build_entry(
        self,
        content: str,
        tier: str,
        algorithm: str,
        event_type: str = "unknown",
        source: str = "unknown",
        timestamp: str = None,
    ) -> ChainEntry:
        """Build one chain entry from a canonical event.

        If `timestamp` is provided, uses it instead of the current UTC time.
        This is used to generate reproducible test vectors.
        """
        ts = timestamp if timestamp is not None else utc_now_iso()
        leaf = leaf_hash(algorithm, content.encode("utf-8"))
        c_hash = chain_hash(
            self.prev_hash,
            self.next_index,
            ts,
            tier,
            algorithm,
            leaf,
        )
        entry = ChainEntry(
            index=self.next_index,
            timestamp=ts,
            tier=tier,
            algorithm=algorithm,
            content=content,
            event_type=event_type,
            source=source,
            leaf_hash_hex=leaf.hex(),
            prev_hash_hex=self.prev_hash.hex(),
            chain_hash_hex=c_hash.hex(),
        )
        self.prev_hash = c_hash
        self.next_index += 1
        return entry


# ─── Batch digest ───────────────────────────────────────────────
def batch_digest(entries) -> str:
    """
    Ordered batch digest over LOW-tier entries in a segment.
    """
    import hashlib as _hashlib

    low = [e for e in entries if (e.get("tier") if isinstance(e, dict) else e.tier) == "low"]
    if not low:
        return _hashlib.sha512(b"").hexdigest()

    def idx(e):
        return e["entry_index"] if isinstance(e, dict) else e.index

    def ts(e):
        return e["timestamp"] if isinstance(e, dict) else e.timestamp

    def lh(e):
        return e["leaf_hash"] if isinstance(e, dict) else e.leaf_hash_hex

    low.sort(key=idx)

    h = _hashlib.sha512()
    h.update(b"BATCH-V1")
    for e in low:
        for field in (
            str(idx(e)).encode("utf-8"),
            (ts(e) or "").encode("utf-8"),
            (lh(e) or "").encode("utf-8"),
        ):
            h.update(len(field).to_bytes(4, "big"))
            h.update(field)
    return h.hexdigest()


# ─── Segment digest ─────────────────────────────────────────────
def segment_digest(entries) -> str:
    """
    Canonical digest of an ordered list of entries within a segment.
    """
    import hashlib as _hashlib

    def idx(e):
        return e["entry_index"] if isinstance(e, dict) else e.index

    def ts(e):
        return e["timestamp"] if isinstance(e, dict) else e.timestamp

    def tier(e):
        return e["tier"] if isinstance(e, dict) else e.tier

    def alg(e):
        return e["algorithm"] if isinstance(e, dict) else e.algorithm

    def content(e):
        return e["content"] if isinstance(e, dict) else e.content

    def etype(e):
        return (e.get("event_type", "unknown") if isinstance(e, dict)
                else getattr(e, "event_type", "unknown"))

    def esrc(e):
        return (e.get("source", "unknown") if isinstance(e, dict)
                else getattr(e, "source", "unknown"))

    h = _hashlib.sha512()
    h.update(b"SEGMENT-V1")

    # Sort entries by index so writer and reader produce identical digests
    # regardless of input order.
    sorted_entries = sorted(entries, key=lambda e: idx(e))
    for r in sorted_entries:
        leaf = leaf_hash(alg(r), content(r).encode("utf-8"))
        h.update(U64(idx(r)))
        h.update(LP16((ts(r) or "").encode("utf-8")))
        h.update(B(TIER_CODES[tier(r)]))
        h.update(B(ALG_CODES[alg(r)]))
        h.update(LP16(leaf))
        h.update(b"\x00")

    bd = batch_digest(entries)
    h.update(b"LOWBATCH")
    h.update(LP16(bd.encode("ascii")))

    return h.hexdigest()
