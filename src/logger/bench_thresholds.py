"""
Threshold sensitivity — honest version.

Reads the STORED tier column, which was assigned at ingestion time by
the actual risk_score() function with the actual thresholds. Does not
re-score, does not re-derive event types, does not fabricate numbers.

If a chain lacks event_type metadata (dev-1, offline-test, windows-live
after restore from a pre-event_type backup), the stored tier column
is still authoritative — it is what the ingestion pipeline produced.
"""
import sys
sys.path.insert(0, ".")
from src.logger.storage import Storage
from collections import Counter


def run():
    s = Storage()
    with s._conn() as c:
        rows = c.execute("SELECT tier FROM entries").fetchall()
    c = Counter(r["tier"] for r in rows)
    return c.get("high", 0), c.get("medium", 0), c.get("low", 0), len(rows)


if __name__ == "__main__":
    h, m, l, tot = run()
    print(f"{'tier':>8} {'count':>8} {'pct':>8}")
    print(f"{'HIGH':>8} {h:>8} {100*h/tot if tot else 0:>7.1f}%")
    print(f"{'MEDIUM':>8} {m:>8} {100*m/tot if tot else 0:>7.1f}%")
    print(f"{'LOW':>8} {l:>8} {100*l/tot if tot else 0:>7.1f}%")
    print(f"{'TOTAL':>8} {tot:>8} 100.0%")
