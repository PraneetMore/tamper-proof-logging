"""
Live dashboard: tiers, online status, last 10 events.
"""

from flask import Flask, jsonify, render_template_string
from src.logger.storage import Storage
from src.logger.verify import verify_all_checkpoints
from src.logger.sync import SyncManager

app = Flask(__name__)
STORAGE = Storage()

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Tamper-Evident Logging — Live</title>
<style>
 body { font-family: monospace; background: #1e1e2e; color: #eee; padding: 20px; }
 h1 { color: #5ecfff; }
 .card { background: #2a2a3e; padding: 16px; border-radius: 8px; margin: 10px 0; }
 .ok   { color: #5eff9e; }
 .bad  { color: #ff5e5e; }
 .tier-high   { color: #ff8a8a; }
 .tier-medium { color: #ffd166; }
 .tier-low    { color: #a3d977; }
 table { width: 100%; border-collapse: collapse; }
 td, th { padding: 6px; text-align: left; border-bottom: 1px solid #444; }
</style>
</head>
<body>
<h1>Tamper-Evident Logging — Live Status</h1>

<div class="card" id="network">
  <b>Server:</b> <span id="server-state">?</span>
</div>

<div class="card" id="per-device">Loading...</div>

<div class="card">
  <b>Recent events (all devices):</b>
  <table>
    <thead><tr><th>Time</th><th>Device</th><th>Event</th><th>Tier</th><th>Algorithm</th></tr></thead>
    <tbody id="recent-events"></tbody>
  </table>
</div>

<script>
async function load() {
  const r = await fetch('/api/status');
  const d = await r.json();

  // Server state
  const s = document.getElementById('server-state');
  s.textContent = d.server_online ? '🟢 ONLINE' : '🔴 OFFLINE';
  s.className = d.server_online ? 'ok' : 'bad';

  // Per-device
  const pd = document.getElementById('per-device');
  let html = '<b>Chains:</b><br>';
  for (const [dev, info] of Object.entries(d.devices)) {
    html += `<div>${dev}: entries=${info.entries} `;
    html += `<span class="tier-high">H=${info.tiers.high}</span> `;
    html += `<span class="tier-medium">M=${info.tiers.medium}</span> `;
    html += `<span class="tier-low">L=${info.tiers.low}</span> `;
    html += `| last_checkpoint=${info.last_checkpoint_seq ?? 'none'} `;
    html += `| verified=<span class="${info.verified?'ok':'bad'}">${info.verified}</span></div>`;
  }
  pd.innerHTML = html;

  // Recent events
  const tb = document.getElementById('recent-events');
  tb.innerHTML = d.recent_events.map(e => `
    <tr>
      <td>${(e.timestamp || '').slice(0, 23)}</td>
      <td>${e.device_id}</td>
      <td>${(e.content || '').slice(0, 60)}</td>
      <td>${e.tier}</td>
      <td>${e.algorithm}</td>
    </tr>
  `).join('');
}
load();
setInterval(load, 5000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def status():
    sync = SyncManager(storage=STORAGE)
    server_online = sync.is_online()

    devices = {}
    for dev in ("dev-1", "windows-1", "offline-test"):
        entries = STORAGE.count_entries(dev)
        if entries == 0:
            continue
        with STORAGE._conn() as c:
            tier_rows = c.execute(
                "SELECT tier, COUNT(*) FROM entries WHERE device_id=? GROUP BY tier",
                (dev,),
            ).fetchall()
            last_cp = c.execute(
                "SELECT seq FROM checkpoints WHERE device_id=? ORDER BY seq DESC LIMIT 1",
                (dev,),
            ).fetchone()

        tiers = {"high": 0, "medium": 0, "low": 0}
        for row in tier_rows:
            tiers[row[0]] = row[1]

        ok, _ = verify_all_checkpoints(STORAGE, dev)
        devices[dev] = {
            "entries": entries,
            "tiers": tiers,
            "last_checkpoint_seq": last_cp["seq"] if last_cp else None,
            "verified": ok,
        }

    with STORAGE._conn() as c:
        recent = c.execute("""
            SELECT device_id, entry_index, timestamp, tier, algorithm, content
            FROM entries ORDER BY timestamp DESC LIMIT 10
        """).fetchall()

    return jsonify({
        "server_online": server_online,
        "devices": devices,
        "recent_events": [dict(r) for r in recent],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
