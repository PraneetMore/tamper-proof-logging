"""
Configuration for the tamper-evident logging framework.
"""

import os
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "logs.db"
CHECKPOINT_DIR = DATA_DIR / "checkpoints"
CHECKPOINT_DIR.mkdir(exist_ok=True)

# ─── Cryptographic constants ──────────────────────────────
GENESIS_LABEL = b"GENESIS-V1"

# ─── Risk scoring thresholds ──────────────────────────────
HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

# ─── Checkpoint cadence ───────────────────────────────────
CHECKPOINT_EVERY_N_ENTRIES = 100
CHECKPOINT_EVERY_SECONDS = 60

# ─── Network sync ─────────────────────────────────────────
SYNC_SERVER_URL = os.environ.get("SYNC_SERVER_URL", "https://localhost:5000")
SYNC_INTERVAL_SECONDS = 60
CONNECTIVITY_TIMEOUT = 3

# ─── High-risk Windows Event IDs ──────────────────────────
WINDOWS_HIGH_RISK_EVENT_IDS = [
    4624,   # successful logon
    4625,   # failed logon
    4672,   # special privileges assigned
    4688,   # process creation
    5379,   # credential manager read
    4798,   # user local group membership enumerated
    4799,   # group membership enumerated
    5382,   # Defender: threat detected
    4634,   # logoff
    4648,   # logon with explicit credentials
]

# ─── High-risk Linux audit types ──────────────────────────
LINUX_HIGH_RISK_AUDIT_TYPES = [
    "LOGIN",
    "USER_AUTH",
    "USER_CMD",
    "EXECVE",
]
