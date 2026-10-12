"""
verify_all.py — Single script that checks every quantitative claim in the paper.
Run from ~/tamper-proof-logging with the venv activated.
"""
import json
import hashlib
import sqlite3
from pathlib import Path

from src.logger.storage import Storage
from src.logger.chain import ChainBuilder

PASS, FAIL = "PASS", "FAIL"
results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append((PASS if ok else FAIL, label, actual, expected))
    mark = "✔" if ok else "✘"
    print(f"  [{mark}] {label}")
    print(f"        actual   = {actual}")
    print(f"        expected = {expected}")


print("=" * 72)
print("PAPER CLAIM VERIFICATION")
print("=" * 72)

# ─────────────────────────────────────────────────────────────────────
# 1. Total entries and checkpoints
# ─────────────────────────────────────────────────────────────────────
print("\n[1] Totals (Table VII, Abstract)")
s = Storage()
with s._conn() as c:
    total_entries = c.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    total_checkpoints = c.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]

check("total native events", total_entries, 39187)
check("total checkpoints", total_checkpoints, 289)

# ─────────────────────────────────────────────────────────────────────
# 2. Per-device breakdown
# ─────────────────────────────────────────────────────────────────────
print("\n[2] Per-device breakdown (Table VII)")

expected_devices = {
    "dev-1":        (1452, 15),
    "windows-1":    (10580, 1),
    "offline-test": (510, 6),
    "windows-live": (26645, 267),
}

with s._conn() as c:
    for dev, (exp_n, exp_cp) in expected_devices.items():
        n = c.execute(
            "SELECT COUNT(*) FROM entries WHERE device_id=?", (dev,)
        ).fetchone()[0]
        cp = c.execute(
            "SELECT COUNT(*) FROM checkpoints WHERE device_id=?", (dev,)
        ).fetchone()[0]
        check(f"{dev} entries", n, exp_n)
        check(f"{dev} checkpoints", cp, exp_cp)

# ─────────────────────────────────────────────────────────────────────
# 3. Tier distribution per device
# ─────────────────────────────────────────────────────────────────────
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
            n = c.execute(
                "SELECT COUNT(*) FROM entries WHERE device_id=? AND tier=?",
                (dev, tier),
            ).fetchone()[0]
            check(f"{dev} / {tier}", n, exp_n)

# Aggregate totals
with s._conn() as c:
    total_high = c.execute(
        "SELECT COUNT(*) FROM entries WHERE tier='high'"
    ).fetchone()[0]
    total_med = c.execute(
        "SELECT COUNT(*) FROM entries WHERE tier='medium'"
    ).fetchone()[0]
    total_low = c.execute(
        "SELECT COUNT(*) FROM entries WHERE tier='low'"
    ).fetchone()[0]

print()
check("aggregate HIGH", total_high, 3430)
check("aggregate MEDIUM", total_med, 5553)
check("aggregate LOW", total_low, 30204)
check("HIGH+MED+LOW = 39187", total_high + total_med + total_low, 39187)

# ─────────────────────────────────────────────────────────────────────
# 4. Checkpoint segment size (windows-live)
# ─────────────────────────────────────────────────────────────────────
print("\n[4] Windows-live checkpoint segment size")
with s._conn() as c:
    rows = c.execute(
        "SELECT segment_end - segment_start + 1 AS size "
        "FROM checkpoints WHERE device_id='windows-live'"
    ).fetchall()
    sizes = [r["size"] for r in rows]

check("windows-live checkpoint count", len(sizes), 267)
check("min segment size", min(sizes), 45)
check("max segment size", max(sizes), 100)
mean = sum(sizes) / len(sizes)
check("mean segment size (round .1)", round(mean, 1), 99.8)

# ─────────────────────────────────────────────────────────────────────
# 5. Storage footprint
# ─────────────────────────────────────────────────────────────────────
print("\n[5] Storage footprint (Table XIII)")
db = Path("data/logs.db")
if db.exists():
    size = db.stat().st_size
    check("SQLite file size (bytes)", size, 42975232)
    bpe = size / total_entries
    check("bytes per entry (round .1)", round(bpe, 1), 1096.7)
else:
    print("  [!] data/logs.db not found — skipping storage check")

# ─────────────────────────────────────────────────────────────────────
# 6. Genesis test vector (Section E.2)
# ─────────────────────────────────────────────────────────────────────
print("\n[6] Genesis test vector (Section E.2)")

def lp16(s: str) -> bytes:
    b = s.encode("utf-8")
    return len(b).to_bytes(2, "big") + b

genesis_actual = hashlib.sha512(
    b"GENESIS-V1" + lp16("test-device") + lp16("test-deploy")
).hexdigest()

genesis_expected = (
    "6372ac2a3ba01dcfd144b8345e11d4e8f50ee0e4274d565e9251926a0ec2017"
    "da8ac3f08b51a3d6c04462e484ed8db794317a4fcac8920ca20e4da6527b67a7a"
)
check("genesis hash", genesis_actual, genesis_expected)

# ─────────────────────────────────────────────────────────────────────
# 7. Attack matrix (local + anchored)
# ─────────────────────────────────────────────────────────────────────
print("\n[7] Attack matrices (Table XII)")

def parse_attack_matrix(path):
    """Return dict {attack_name: (detected, trials)}."""
    out = {}
    p = Path(path)
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("Anchored") or line.startswith("Attack"):
            continue
        # rows look like: "modification ...  detected  5000/5000  recall=..."
        if "detected" not in line:
            continue
        parts = line.split()
        try:
            di = parts.index("detected")
            trial_str = parts[di + 1]
            d, n = trial_str.split("/")
            name = " ".join(parts[:di])
            out[name] = (int(d), int(n))
        except (ValueError, IndexError):
            continue
    return out

local_matrix = parse_attack_matrix("data/evidence/attack_matrix_extended.txt")
anchored_matrix = parse_attack_matrix("data/evidence/attack_matrix_anchored.txt")

print("  local matrix:")
if local_matrix:
    for k, v in local_matrix.items():
        print(f"    {k:40} {v[0]}/{v[1]}")
else:
    print("    [!] file missing")

print("  anchored matrix:")
if anchored_matrix:
    for k, v in anchored_matrix.items():
        print(f"    {k:40} {v[0]}/{v[1]}")
else:
    print("    [!] file missing")

# ─────────────────────────────────────────────────────────────────────
# 8. Bench files existence
# ─────────────────────────────────────────────────────────────────────
print("\n[8] Benchmark evidence files")
for fname in [
    "bench_baselines.txt",
    "benchmark_ci.txt",
    "bench_verify_ci.txt",
    "threshold_sensitivity.txt",
    "tier_distribution.txt",
    "storage_footprint.txt",
]:
    p = Path("data/evidence") / fname
    exists = p.exists()
    print(f"  [{'✔' if exists else '✘'}] {fname}"
          + (f"  ({p.stat().st_size} bytes)" if exists else "  MISSING"))

# ─────────────────────────────────────────────────────────────────────
# 9. Attacker capability map — who is detected / not detected
# ─────────────────────────────────────────────────────────────────────
print("\n[9] Attack detection summary (matches Table XII)")
attack_claims = {
    "modification":            (5000, 5000, "in-scope"),
    "deletion":                (5000, 5000, "in-scope"),
    "insertion_inside":        (5000, 5000, "in-scope"),
    "truncation in-segment":   (100,  100,  "in-scope"),
    "post-cp insertion":       (0,    100,  "out-of-scope"),
    "event_type tamper":       (0,    100,  "out-of-scope"),
    "cp continuity break":     (100,  100,  "in-scope"),
    "low-tier batch tamper":   (100,  100,  "in-scope"),
}
if local_matrix:
    for claim_name, (exp_d, exp_n, scope) in attack_claims.items():
        # find closest matching key
        key = next(
            (k for k in local_matrix if claim_name.lower() in k.lower()),
            None,
        )
        if key is None:
            print(f"  [!] not found in local matrix: {claim_name}")
            continue
        d, n = local_matrix[key]
        check(
            f"{claim_name} ({scope})",
            (d, n),
            (exp_d, exp_n),
        )

# ─────────────────────────────────────────────────────────────────────
# Final report
# ─────────────────────────────────────────────────────────────────────
print()
print("=" * 72)
n_pass = sum(1 for r in results if r[0] == PASS)
n_fail = sum(1 for r in results if r[0] == FAIL)
print(f"TOTAL: {n_pass} passed, {n_fail} failed")
print("=" * 72)

if n_fail:
    print("\nFAILURES:")
    for status, label, actual, expected in results:
        if status == FAIL:
            print(f"  ✘ {label}")
            print(f"       actual   = {actual}")
            print(f"       expected = {expected}")

print("\nDone. Copy this output for your records.")
