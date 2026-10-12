"""
HMAC-SHA-512 chain step. Parallel to chain_hash() in chain.py,
but with a key.

The key is stored in data/chain_key.bin with file mode 0600.
This protects against a privileged offline attacker who can
read the database but not the key file.
"""
import hashlib
import hmac
import os
from pathlib import Path


KEY_PATH = Path("data/chain_key.bin")


def load_or_create_key(path: Path = KEY_PATH) -> bytes:
    """Load the chain key from disk, or generate one on first run."""
    if path.exists():
        return path.read_bytes()
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass  # Windows or restricted FS
    return key


def keyed_chain_hash(key: bytes, prev: bytes, entry_index: int,
                     timestamp: str, tier: str, algorithm: str,
                     leaf: bytes) -> bytes:
    """HMAC-SHA-512 version of chain_hash(). Same field layout."""
    from .chain import U64, LP16, B, TIER_CODES, ALG_CODES
    msg = (
        prev
        + U64(entry_index)
        + LP16(timestamp.encode("utf-8"))
        + B(TIER_CODES[tier])
        + B(ALG_CODES[algorithm])
        + LP16(leaf)
    )
    return hmac.new(key, msg, hashlib.sha512).digest()


def keyed_genesis(key: bytes, device_id: str, deployment_id: str) -> bytes:
    """HMAC version of genesis_hash()."""
    from .chain import LP16
    msg = (
        b"GENESIS-V1"
        + LP16(device_id.encode("utf-8"))
        + LP16(deployment_id.encode("utf-8"))
    )
    return hmac.new(key, msg, hashlib.sha512).digest()
