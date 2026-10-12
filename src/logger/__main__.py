"""
CLI entry point for the tamper-evident logging framework.

Subcommands:
  append  — append a manual event to a device chain
  status  — show per-device entry/checkpoint counts
  verify  — verify all checkpoints across known devices
"""
import argparse
import sys

from .storage import Storage
from .verify import verify_all_checkpoints
from .chain import ChainBuilder

DEVICES = ("dev-1", "windows-1", "offline-test", "windows-live")


def cmd_append(args):
    s = Storage()
    device = args.device
    start_index = s.count_entries(device)
    last = s.last_entry(device)

    builder = ChainBuilder(device, f"{device}-deployment", start_index)
    if last is not None:
        builder.prev_hash = bytes.fromhex(last["chain_hash"])

    entry = builder.build_entry(
        args.message,
        tier=args.tier,
        algorithm=args.algorithm,
    )
    s.insert_entries_batch([entry], device_id=device)
    print(f"[OK] appended to {device}: index={entry.index}, tier={entry.tier}, alg={entry.algorithm}")


def cmd_status(args):
    s = Storage()
    print(f"{'device':15} {'entries':>8} {'checkpoints':>12}")
    for dev in DEVICES:
        n = s.count_entries(dev)
        with s._conn() as c:
            cps = c.execute(
                'SELECT COUNT(*) FROM checkpoints WHERE device_id=?', (dev,)
            ).fetchone()[0]
        print(f"{dev:15} {n:>8} {cps:>12}")


def cmd_verify(args):
    s = Storage()
    any_checked = False
    for dev in DEVICES:
        if s.count_entries(dev) == 0:
            continue
        any_checked = True
        ok, msg = verify_all_checkpoints(s, dev)
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {dev}: {msg}")
    if not any_checked:
        print("No devices have entries.")


def main():
    p = argparse.ArgumentParser(description="Tamper-evident logging CLI")
    sub = p.add_subparsers(dest="command")

    ap = sub.add_parser("append", help="Append a manual event")
    ap.add_argument("--device", "-d", default="dev-1")
    ap.add_argument("--message", "-m", required=True)
    ap.add_argument("--tier", "-t", default="high",
                    choices=["high", "medium", "low"])
    ap.add_argument("--algorithm", "-a", default="sha512",
                    choices=["sha512", "blake2s", "batch"])
    ap.set_defaults(func=cmd_append)

    sp = sub.add_parser("status", help="Show per-device status")
    sp.set_defaults(func=cmd_status)

    vp = sub.add_parser("verify", help="Verify all device chains")
    vp.add_argument("--full", action="store_true",
                    help="(no-op; kept for compatibility)")
    vp.set_defaults(func=cmd_verify)

    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
