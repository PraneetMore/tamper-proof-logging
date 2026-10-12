"""Regenerate figures 3, 4, 5 from current data."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

OUT = Path("data/evidence")
OUT.mkdir(parents=True, exist_ok=True)

# Fig 3 — Performance decomposition
fig, ax = plt.subplots(figsize=(6, 4))
labels = ["Leaf\nhashing", "In-memory\nchain", "Persistent\npipeline"]
values = [972435, 185114, 19126]
ax.bar(labels, values, color=["#4C72B0", "#55A868", "#C44E52"])
ax.set_ylabel("Throughput (logs/sec)")
ax.set_yscale("log")
ax.set_title("Performance decomposition")
for i, v in enumerate(values):
    ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(OUT / "fig6_performance.png", dpi=200)
plt.close()

# Fig 4 — Verification latency
seg = [100, 500, 1000, 2000, 5000, 10000]
times = [1.09, 3.27, 6.46, 14.54, 31.91, 72.88]
fig, ax = plt.subplots(figsize=(6, 4))
ax.plot(seg, times, "o", color="#4C72B0", label="measured")
coef = np.polyfit(seg, times, 1)
ax.plot(seg, np.polyval(coef, seg), "--", color="#C44E52",
        label=f"fit: {coef[0]*1000:.1f} µs/entry")
ax.set_xlabel("Segment length (entries)")
ax.set_ylabel("Verification time (ms)")
ax.set_title("Verification latency vs segment length")
ax.legend()
plt.tight_layout()
plt.savefig(OUT / "fig7_verify.png", dpi=200)
plt.close()

# Fig 5 — Attack matrix
fig, ax = plt.subplots(figsize=(8, 4))
attacks = ["Modification", "Deletion", "Insertion\n(in-segment)",
           "Truncation\n(out-of-scope)", "Post-cp\n(out-of-scope)"]
recalls = [100.0, 100.0, 100.0, 0.0, 0.0]
colors = ["#55A868"]*3 + ["#C44E52"]*2
ax.bar(attacks, recalls, color=colors)
ax.set_ylabel("Observed recall (%)")
ax.set_ylim(0, 110)
ax.set_title("Attack-class matrix")
for i, v in enumerate(recalls):
    ax.text(i, v + 2, f"{v:.1f}%", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig(OUT / "fig8_attack.png", dpi=200)
plt.close()

print(f"Wrote figures to {OUT}")
