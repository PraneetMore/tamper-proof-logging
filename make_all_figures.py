import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ─── Fig. 6 — performance decomposition ───
layers = ["Leaf hashing\n(BLAKE2s-256)", "In-memory chain", "Persistent pipeline"]
throughputs = [1057092, 173467, 18519]
colors = ["#5CB85C", "#F0AD4E", "#D9534F"]
fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.bar(layers, throughputs, color=colors, width=0.6)
ax.set_ylabel("Throughput (ops/sec or logs/sec)")
ax.set_title("Fig. 6. Performance decomposition", fontweight="bold")
ax.set_yscale("log")
for bar, val in zip(bars, throughputs):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.15,
            f"{val:,}", ha="center", fontsize=10, fontweight="bold")
ax.set_ylim(1e3, 3e6)
plt.tight_layout()
plt.savefig("data/evidence/fig6_performance.png", dpi=300)
plt.close()

# ─── Fig. 7 — verification latency ───
lengths = [100, 500, 1000, 2000, 5000, 10000]
times = [1.14, 3.03, 6.31, 14.02, 29.96, 63.79]
coeffs = np.polyfit(lengths, times, 1)
fit_y = np.polyval(coeffs, lengths)
residuals = np.array(times) - fit_y
r_squared = 1 - np.sum(residuals**2) / np.sum((np.array(times) - np.mean(times))**2)
fig, ax = plt.subplots(figsize=(8, 4.5))
ax.plot(lengths, times, "o-", color="#5CB85C", linewidth=2, markersize=8, label="Measured")
ax.plot(lengths, fit_y, "--", color="#D9534F",
        label=f"Linear fit: {coeffs[0]*1000:.2f} µs/entry, R² = {r_squared:.4f}")
ax.set_xlabel("Segment length (entries)")
ax.set_ylabel("Verification time (ms)")
ax.set_title("Fig. 7. Verification time vs segment length", fontweight="bold")
ax.grid(True, alpha=0.3)
ax.legend()
plt.tight_layout()
plt.savefig("data/evidence/fig7_verify.png", dpi=300)
plt.close()

# ─── Fig. 8 — attack matrix ───
attacks = ["Modification", "Deletion", "Insertion\n(inside segment)"]
detected = [5000, 5000, 5000]
missed = [0, 0, 0]
x = np.arange(len(attacks))
fig, ax = plt.subplots(figsize=(7, 4.5))
b1 = ax.bar(x - 0.175, detected, 0.35, label="Detected", color="#5CB85C")
b2 = ax.bar(x + 0.175, missed, 0.35, label="Missed", color="#D9534F")
ax.set_ylabel("Trials (out of 5,000)")
ax.set_title("Fig. 8. Implementation-level attack matrix", fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(attacks)
ax.legend()
ax.set_ylim(0, 5500)
plt.tight_layout()
plt.savefig("data/evidence/fig8_attack.png", dpi=300)
plt.close()

print("Generated: fig6_performance.png, fig7_verify.png, fig8_attack.png")
print(f"Verification regression: slope={coeffs[0]*1000:.3f} us/entry, intercept={coeffs[1]:.3f} ms, R^2={r_squared:.4f}")
