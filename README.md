# Tamper-Evident Logging Framework

A cross-platform tamper-evident logging framework with risk-adaptive
commitment, keyed HMAC-SHA-512 variants, mutual TLS, and offline
checkpoint synchronization.

## Overview

The framework collects native log events on Windows Security Event Log
(via `win32evtlog`) and Kali Linux journald, scores each event with a
deterministic rule-based function (0–100), commits them to a SHA-512
hash chain with tiered per-event commitment (SHA-512 for HIGH,
BLAKE2s-256 for MEDIUM and LOW), and periodically creates checkpoints.
Checkpoints are appended to a remote append-only JSONL store over
mutual TLS when the server is reachable and retained locally otherwise.

An optional keyed variant replaces the unkeyed chain step with
HMAC-SHA-512 to defend against a privileged offline attacker.

## Repository Layout

    src/logger/          Core modules
      chain.py           Leaf hashing, chain hashing, segment digests
      keyed_chain.py     HMAC-SHA-512 chain step
      storage.py         SQLite persistence
      adaptive.py        Risk scoring and tier selection
      collector.py       Windows Event Log, ausearch, journalctl
      sync.py            Checkpoint creation and TLS POST
      verify.py          Verification with optional trusted reference
      monitor.py         Continuous collection
      attack_test*.py    Attack matrices
      bench_*.py         Benchmarks
      merkle_log.py      Merkle-tree baseline
    server.py            Flask HTTPS checkpoint server
    dashboard.py         Live dashboard (port 5001)
    scripts/             Import and generation scripts
    data/
      logs.db            SQLite database (39,187 entries, 289 checkpoints)
      server_store/      Per-device JSONL checkpoint store
      evidence/          Benchmark and attack evidence files
      tls/               Self-signed certificates for the demo
    verify_all.py        Verify all device chains
    verify_everything.py Verify every quantitative claim in the paper

## Requirements

- Python 3.14+
- SQLite 3.53+
- Flask
- requests
- pywin32 (on the Windows collector only)

Install:

    pip install -r requirements.txt

## Running The Framework

Start the checkpoint server:

    python server.py

In another terminal, run the monitor:

    python -m src.logger.monitor

In another terminal, run the dashboard:

    python dashboard.py

Then open `https://127.0.0.1:5001` in a browser.

## Verification

Verify all device chains:

    python verify_all.py

Verify every quantitative claim in the paper:

    python verify_everything.py

## Attack Matrix

Run the unkeyed attack matrix:

    python -m src.logger.attack_test

Run the anchored attack matrix:

    python -m src.logger.attack_test_anchored

Run the keyed and adaptive attack matrix:

    python -m src.logger.attack_test_keyed

## Benchmarks

    python -m src.logger.benchmark_ci       # isolated, in-memory, persistent
    python -m src.logger.bench_baselines    # uniform, adaptive, keyed, Merkle
    python -m src.logger.bench_batched      # per-entry vs batched commits
    python -m src.logger.bench_verify_ci    # verification time vs segment length

## Security Boundary

- **Local consistency:** the verifier recomputes leaf hashes, chain hashes,
  segment digests, and checkpoint digests from stored content.
- **Anchored integrity:** when a `trusted_reference` mapping is supplied,
  each locally computed checkpoint digest is compared against the reference.
- **Endpoint authenticity:** when mutual TLS is enabled, the server rejects
  clients that do not present a valid client certificate.

The attack harness and the verifier were written by the same authors.
The results demonstrate implementation correctness, not adversarial
resistance in the presence of an independent attacker.

## License

Not yet chosen. Contact the author before redistributing.
