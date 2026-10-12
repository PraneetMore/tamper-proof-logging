"""
Append-only checkpoint server.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

STORE_DIR = Path("data/server_store")
STORE_DIR.mkdir(parents=True, exist_ok=True)


def _store_path(device_id: str) -> Path:
    return STORE_DIR / f"{device_id}.jsonl"


def _read_all(device_id: str):
    p = _store_path(device_id)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _last(device_id: str):
    records = _read_all(device_id)
    return records[-1] if records else None


@app.route("/status", methods=["GET"])
def status():
    devices = [p.stem for p in STORE_DIR.glob("*.jsonl")]
    return jsonify({"devices": devices})


@app.route("/checkpoint/<device_id>", methods=["GET"])
def get_device(device_id):
    return jsonify({"device_id": device_id, "checkpoints": _read_all(device_id)})


@app.route("/checkpoint", methods=["POST"])
def receive():
    cp = request.get_json(force=True, silent=True)
    if not cp:
        return jsonify({"error": "no JSON body"}), 400

    # Accept either 'seq' (SQLite column name) or 'sequence'
    if "seq" in cp and "sequence" not in cp:
        cp["sequence"] = cp["seq"]

    required = [
        "device_id", "sequence", "segment_start", "segment_end",
        "chain_start", "chain_end", "timestamp", "prev_digest",
        "checkpoint_digest",
    ]
    for f in required:
        if f not in cp:
            return jsonify({"error": f"missing field {f}"}), 400

    last = _last(cp["device_id"])

    # Idempotent duplicate handling: if the same checkpoint is resubmitted
    # with an identical digest, accept without re-storing.
    if last is not None and cp["sequence"] == last["sequence"]:
        if cp["checkpoint_digest"] == last["checkpoint_digest"]:
            return jsonify({"status": "duplicate", "sequence": cp["sequence"]}), 200
        return jsonify({"error": "conflicting checkpoint for sequence"}), 409

    if last is not None:
        if cp["sequence"] != last["sequence"] + 1:
            return jsonify({"error": "sequence not strictly consecutive"}), 409
        if cp["prev_digest"] != last["checkpoint_digest"]:
            return jsonify({"error": "prev_digest does not match"}), 409
        # Chain-head continuity: new segment starts where previous ended
        if cp["chain_start"] != last["chain_end"]:
            return jsonify({"error": "chain_start does not match previous chain_end"}), 409
        # Segment-index continuity: no gaps or overlaps
        if cp["segment_start"] != last["segment_end"] + 1:
            return jsonify({"error": "segment_start is not previous segment_end + 1"}), 409

    # Recompute the checkpoint digest from canonical fields and compare.
    # This ensures the client-supplied digest is self-consistent and
    # cannot be a fabricated value.
    try:
        from src.logger.sync import checkpoint_digest
        recomputed = checkpoint_digest(cp)
        if recomputed != cp["checkpoint_digest"]:
            return jsonify({"error": "checkpoint_digest does not match recomputed value"}), 400
    except Exception as e:
        return jsonify({"error": f"digest recomputation failed: {e}"}), 400

    cp["received_at"] = datetime.now(timezone.utc).isoformat()
    with _store_path(cp["device_id"]).open("a") as f:
        f.write(json.dumps(cp) + "\n")

    return jsonify({"status": "stored", "sequence": cp["sequence"]}), 200

@app.route("/windows-event", methods=["POST"])
def windows_event():
    """
    Receive a live Windows Security Event from a remote collector
    and commit it to the chain under device_id='windows-live'.
    """
    from src.logger.adaptive import tier_for
    from src.logger.chain import ChainBuilder
    from src.logger.storage import Storage

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "no json body"}), 400

    required = ["device_id", "event_id", "timestamp", "content"]
    for f in required:
        if f not in data:
            return jsonify({"error": f"missing field {f}"}), 400

    device_id = data["device_id"]
    event_type = f"windows_{data['event_id']}"
    content = data["content"]

    tier, alg, score = tier_for(event_type, content)

    storage = Storage()
    start_index = storage.count_entries(device_id)
    last_entry = storage.last_entry(device_id)

    builder = ChainBuilder(device_id, "windows-live-deployment", start_index)
    if last_entry is not None:
        builder.prev_hash = bytes.fromhex(last_entry["chain_hash"])

    entry = builder.build_entry(content, tier, alg)
    storage.insert_entry(entry, device_id=device_id)

    return jsonify({
        "status": "stored",
        "index": entry.index,
        "tier": tier,
        "algorithm": alg,
        "score": score,
    }), 200

if __name__ == "__main__":
    print("Checkpoint server running on https://localhost:5000")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        ssl_context=("data/tls/server.crt", "data/tls/server.key"),
    )
