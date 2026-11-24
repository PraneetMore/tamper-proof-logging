# Tamper-Evident Logging Framework

A tamper-evident logging framework for Windows and Kali Linux endpoints, with risk-adaptive tiering, an optional keyed HMAC-SHA-512 chain, and offline checkpoint synchronization.

Companion code and data for the paper *"A Tamper-Evident Logging Framework with Risk-Adaptive Tiering and Offline Checkpoint Synchronization"* by Praneet More and Adarsh Patel (VIT Bhopal University).

## Overview

The framework collects native log events from the Windows Security Event Log (via `win32evtlog`) and from Kali Linux journald or auditd. Each event is scored with a deterministic rule-based function (0–100), and its score picks a tier:

| Tier   | Score    | Leaf commitment                                   |
|--------|----------|---------------------------------------------------|
| HIGH   | 70 or more | SHA-512                                         |
| MEDIUM | 40–69    | BLAKE2s-256                                       |
| LOW    | below 40 | SHA-512, plus a batch digest at each checkpoint   |

Every entry is linked into a single SHA-512 hash chain. A checkpoint is created every 100 entries or 60 seconds. Checkpoints are sent over HTTPS to a remote append-only JSONL store when the server is reachable, and are kept locally otherwise, so the chain keeps growing while the host is offline.

An optional keyed variant replaces the unkeyed chain step with HMAC-SHA-512 to defend against a privileged offline attacker who can edit the database but cannot read the key file.

On Windows, events are only collected and forwarded. Scoring, chaining, checkpointing, verification and the server all run on the Kali host.

## Repository layout

```
src/logger/          Core modules
  chain.py           Leaf hashing, chain hashing, segment digests
  keyed_chain.py     HMAC-SHA-512 chain step (key in data/chain_key.bin, not published)
  storage.py         SQLite persistence
  adaptive.py        Risk scoring and tier selection
  collector.py       Windows Event Log, ausearch, journalctl
  sync.py            Checkpoint creation and HTTPS POST
  verify.py          Verification with optional trusted reference
  monitor.py         Continuous collection
  attack_test*.py    Attack matrices
  bench_*.py         Benchmarks
  merkle_log.py      Merkle-tree baseline
server.py            Flask HTTPS checkpoint server (port 5000)
dashboard.py         Live dashboard (HTTP, port 5001)
scripts/             Import and log-generation scripts
data/
  logs.db            SQLite database used in the paper: 39,187 entries in four
                     chains (dev-1, windows-1, offline-test, windows-live),
                     289 checkpoints
  server_store/      Per-device JSONL checkpoint store
  evidence/          Benchmark and attack evidence files
  tls/               Public certificates only; private keys are not published
paper/figures/       Source of Fig. 1
verify_all.py        Verify all device chains
verify_everything.py Re-check the quantitative claims in the paper
```

## Requirements

- Python 3.14+
- SQLite 3.53+
- Flask, requests
- pywin32 (on the Windows collector only)
- On Kali, `ausearch` comes from auditd: `sudo apt install auditd`

Install:

```
pip install -r requirements.txt
```

## TLS certificates

The private keys are not in the repository. After cloning, create your own self-signed pair:

```
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout data/tls/server.key -out data/tls/server.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=tel-client" \
  -keyout data/tls/client.key -out data/tls/client.crt
```

## Running the framework

Start the checkpoint server:

```
python server.py
```

In another terminal, run the monitor:

```
python -m src.logger.monitor
```

In another terminal, run the dashboard:

```
python dashboard.py
```

Then open `http://127.0.0.1:5001` in a browser.

## Verification

Verify all device chains:

```
python verify_all.py
```

Re-check the quantitative claims in the paper:

```
python verify_everything.py
```

## Attack matrix

```
python -m src.logger.attack_test            # unkeyed attack matrix
python -m src.logger.attack_test_anchored   # anchored attack matrix
python -m src.logger.attack_test_keyed      # keyed and adaptive attackers
```

## Benchmarks

```
python -m src.logger.benchmark_ci       # isolated, in-memory, persistent
python -m src.logger.bench_baselines    # uniform, adaptive, keyed, Merkle
python -m src.logger.bench_batched      # single transaction vs chunked 10,000-row commits (WAL)
python -m src.logger.bench_verify_ci    # verification time vs segment length
```

## Security boundary

- **Local consistency:** the verifier recomputes leaf hashes, chain hashes, segment digests and checkpoint digests from the stored content.
- **Anchored integrity:** when a `trusted_reference` mapping is supplied, each locally computed checkpoint digest is compared against the reference held by the server.
- **Endpoint authenticity: not provided.** The server presents a self-signed certificate but does not request client certificates. The client (`sync.py`) does not verify the server's certificate (`verify=False`). TLS therefore only protects against passive eavesdropping. Mutual TLS is future work.

## Known limitations

- The event type was used for scoring but not stored with most entries in `data/logs.db` (28,568 of 39,187). Tiers were assigned before storage, so no tier, commitment or verification result is affected. `insert_entry` now stores it. The Kali monitor path (`build_entry` in `monitor.py`) does not yet pass it on.
- Windows events are forwarded to the Kali host before they are committed, so that network path must be trusted.
- The attack harness and the verifier were written by the same authors. The results demonstrate implementation correctness, not resistance to an independent attacker.
- All experiments ran on a single virtual machine.

## Data note

`data/logs.db` contains real events from the authors' test machines, including the Windows host name and the local account name.

## License

Not yet chosen. Contact the author before redistributing.
