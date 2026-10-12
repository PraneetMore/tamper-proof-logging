"""
verify_everything.py — checks every quantitative claim in the paper.

Run from ~/tamper-proof-logging with the venv activated.
"""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

# Ensure project is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.logger.storage import Storage
from src.logger.sync import checkpoint_digest

PASS = "PASS"
FAIL = "FAIL"
rows = []


def check(label, actual, expected, tol=0):
    """tol: tolerance for floating-point comparisons."""
    if tol:
        ok = abs(actual - expected) <= tol
    else:
        ok = actual == expected
    rows.append((ok, label, actual, expected))
    mark = "OK " if ok else "FAIL"
    print(f"[{mark}] {label}")
    print(f"       actual   = {actual}")
    print(f"       expected = {expected}")


print("=" * 72)
print("PAPER CLAIM VERIFICATION")
print("=" * 72)

s = Storage()

# ─── 1. TOTAL ENTRIES AND CHECKPOINTS ────────────────────────────────
print("\n[1] Totals (Abstract, Table VII)")
with s._conn() as c:
    total_e = c.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    total_c = c.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
check("Total native entries", total_e, 39187)
check("Total checkpoints", total_c, 289)

# ─── 2. PER-DEVICE ENTRIES AND CHECKPOINTS ───────────────────────────
print("\n[2] Per-device counts (Table VII)")
devices = {
    "dev-1":        (1452, 15),
    "windows-1":    (10580, 1),
    "offline-test": (510, 6),
    "windows-live": (26645, 267),
}
with s._conn() as c:
    for dev, (exp_e, exp_c) in devices.items():
        n_e = c.execute("SELECT COUNT(*) FROM entries WHERE device_id=?", (dev,)).fetchone()[0]
        n_c = c.execute("SELECT COUNT(*) FROM checkpoints WHERE device_id=?", (dev,)).fetchone()[0]
        check(f"{dev:15} entries", n_e, exp_e)
        check(f"{dev:15} checkpoints", n_c, exp_c)

# ─── 3. TIER DISTRIBUTION ────────────────────────────────────────────
print("\n[3] Tier distribution (Table VIII)")
expected_tiers = {
    "dev-1":        {"high": 409,  "medium": 1043, "low": 0},
    "windows-1":    {"high": 1081, "medium": 915,  "low": 8584},
    "offline-test": {"high": 144,  "medium": 366,  "low": 0},
    "windows-live": {"high": 1796, "medium": 3229, "low": 21620},
}
with s._conn() as c:
    for dev, exp in expected_tiers.items():
        for tier, exp_n in exp.items():
            n = c.execute("SELECT COUNT(*) FROM entries WHERE device_id=? AND tier=?",
                          (dev, tier)).fetchone()[0]
            check(f"{dev:15} {tier:6}", n, exp_n)

with s._conn() as c:
    agg_h = c.execute("SELECT COUNT(*) FROM entries WHERE tier='high'").fetchone()[0]
    agg_m = c.execute("SELECT COUNT(*) FROM entries WHERE tier='medium'").fetchone()[0]
    agg_l = c.execute("SELECT COUNT(*) FROM entries WHERE tier='low'").fetchone()[0]
check("aggregate HIGH", agg_h, 3430)
check("aggregate MEDIUM", agg_m, 5553)
check("aggregate LOW", agg_l, 30204)
check("HIGH+MEDIUM+LOW", agg_h + agg_m + agg_l, 39187)

# ─── 4. WINDOWS-LIVE CHECKPOINT SIZES ────────────────────────────────
print("\n[4] windows-live checkpoint sizes (Section VI-A)")
with s._conn() as c:
    sizes = [r[0] for r in c.execute(
        "SELECT segment_end - segment_start + 1 FROM checkpoints WHERE device_id='windows-live'"
    )]
check("checkpoint count", len(sizes), 267)
check("min segment size", min(sizes), 45)
check("max segment size", max(sizes), 100)
check("mean segment size (round 0.1)", round(sum(sizes)/len(sizes), 1), 99.8)
check("median segment size", sorted(sizes)[len(sizes)//2], 100)

# ─── 5. STORAGE FOOTPRINT ────────────────────────────────────────────
print("\n[5] Storage footprint (Table XIII)")
db_size = Path("data/logs.db").stat().st_size
check("Main SQLite file size (bytes)", db_size, 42975232)
bpe = db_size / total_e
check("Bytes per entry (round 0.1)", round(bpe, 1), 1096.7)

# ─── 6. GENESIS TEST VECTOR ──────────────────────────────────────────
print("\n[6] Genesis test vector (Section IV-E.2)")
def lp16(x):
    b = x.encode("utf-8")
    return len(b).to_bytes(2, "big") + b
genesis = hashlib.sha512(
    b"GENESIS-V1" + lp16("test-device") + lp16("test-deploy")
).hexdigest()
expected_genesis = (
    "6372ac2a3ba01dcfd144b8345e11d4e8f50ee0e4274d565e9251926a0ec2017"
    "da8ac3f08b51a3d6c04462e484ed8db794317a4fcac8920ca20e4da6527b67a7a"
)
check("genesis hash", genesis, expected_genesis)

# ─── 7. EVERY CHECKPOINT DIGEST MATCHES RECOMPUTATION ────────────────
print("\n[7] Checkpoint digest self-consistency")
with s._conn() as c:
    mismatches = 0
    total = 0
    for row in c.execute("SELECT * FROM checkpoints"):
        total += 1
        cp = dict(row)
        cp["sequence"] = cp.pop("seq")
        if cp["checkpoint_digest"] != checkpoint_digest(cp):
            mismatches += 1
            print(f"       MISMATCH: {cp['device_id']} seq={cp['sequence']}")
check("checkpoints recomputed", total, 289)
check("digest mismatches", mismatches, 0)

# ─── 8. JSONL STORE MATCHES SQLITE ───────────────────────────────────
print("\n[8] JSONL store matches SQLite (Section V-E)")
server_store = Path("data/server_store")
if not server_store.exists():
    print("       [FAIL] data/server_store/ does not exist")
else:
    for dev, (_, exp_c) in devices.items():
        p = server_store / f"{dev}.jsonl"
        if not p.exists():
            check(f"{dev:15} JSONL lines", 0, exp_c)
            continue
        lines = [ln for ln in p.read_text().splitlines() if ln.strip()]
        check(f"{dev:15} JSONL lines", len(lines), exp_c)

# ─── 9. SERVER-ACCEPTED CHECKPOINTS HAVE received_at ─────────────────
print("\n[9] JSONL records have server-generated received_at")
for dev in devices:
    p = server_store / f"{dev}.jsonl"
    if not p.exists():
        continue
    first = json.loads(p.read_text().splitlines()[0])
    has_field = "received_at" in first
    mark = "OK " if has_field else "FAIL"
    print(f"[{mark}] {dev:15} first record has received_at = {has_field}")
    rows.append((has_field, f"{dev} received_at", has_field, True))

# ─── 10. ATTACK MATRIX FILES PRESENT AND PARSEABLE ───────────────────
print("\n[10] Attack matrix evidence files")
for fname in ["attack_matrix_extended.txt", "attack_matrix_anchored.txt"]:
    p = Path("data/evidence") / fname
    if p.exists():
        content = p.read_text()
        ok = "detected" in content
        print(f"[{'OK ' if ok else 'FAIL'}] {fname} present and parseable")
        rows.append((ok, fname, True, True))
    else:
        print(f"[FAIL] {fname} MISSING")
        rows.append((False, fname, False, True))

# ─── 11. BENCHMARK EVIDENCE FILES ────────────────────────────────────
print("\n[11] Benchmark evidence files")
for fname in ["benchmark_ci.txt", "bench_baselines.txt", "bench_verify_ci.txt",
              "threshold_sensitivity.txt", "tier_distribution.txt", "storage_footprint.txt"]:
    p = Path("data/evidence") / fname
    present = p.exists()
    print(f"[{'OK ' if present else 'FAIL'}] {fname}"
          + (f" ({p.stat().st_size} bytes)" if present else " MISSING"))
    rows.append((present, fname, present, True))

# ─── 12. ENVIRONMENT ─────────────────────────────────────────────────
print("\n[12] Environment (Section V-A)")
import platform
pyver = platform.python_version()
sqlite_ver = sqlite3.sqlite_version
check("Python version", pyver, "3.14.6")
check("SQLite version", sqlite_ver, "3.53.4")

# ─── SUMMARY ─────────────────────────────────────────────────────────
print("\n" + "=" * 72)
n_pass = sum(1 for r in rows if r[0])
n_fail = len(rows) - n_pass
print(f"TOTAL: {n_pass} passed, {n_fail} failed")
print("=" * 72)

if n_fail:
    print("\nFAILURES:")
    for ok, label, actual, expected in rows:
        if not ok:
            print(f"  FAIL {label}")
            print(f"       actual   = {actual}")
            print(f"       expected = {expected}")

print("\nDone.")
