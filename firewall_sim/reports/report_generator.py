"""Metrics, text summaries, and matplotlib charts for a firewall run."""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate traffic, detection, and ground-truth classification metrics."""
    allowed = sum(r.get("action") == "ALLOW" for r in records)
    blocked = sum(r.get("action") in {"DENY", "DROP"} for r in records)
    alerts = sum(bool(r.get("alerts")) for r in records)
    tp = sum(r.get("is_attack", False) and r.get("action") in {"DENY", "DROP"} for r in records)
    tn = sum(not r.get("is_attack", False) and r.get("action") == "ALLOW" for r in records)
    fp = sum(not r.get("is_attack", False) and r.get("action") in {"DENY", "DROP"} for r in records)
    fn = sum(r.get("is_attack", False) and r.get("action") == "ALLOW" for r in records)
    total = len(records)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    blocked_ips = Counter(r["src_ip"] for r in records
                          if r.get("is_attack") and r.get("action") in {"DENY", "DROP"})
    attacks = Counter(a.attack_type for r in records for a in r.get("alerts", []))
    rules = Counter(r.get("rule_id") for r in records if r.get("rule_id"))
    return {
        "total": total, "allowed": allowed, "blocked": blocked, "alerts": alerts,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "accuracy": accuracy,
        "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr,
        "legit_allowed_rate": tn / (tn + fp) if tn + fp else 0.0,
        "blocked_ips": blocked_ips, "attacks": attacks, "rules": rules,
    }


def _label_bars(ax: Any, bars: Any) -> None:
    for bar in bars:
        ax.text(bar.get_width() + 0.02, bar.get_y() + bar.get_height() / 2,
                str(int(bar.get_width())), va="center")


def _save(fig: Any, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    import matplotlib.pyplot as plt
    plt.close(fig)


def _charts(records: list[dict[str, Any]], output: Path, mode: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    summary = summarize_records(records)
    title = mode.title()
    colors = ["#2ca02c", "#d62728"]
    fig, ax = plt.subplots(figsize=(7, 5))
    values = [summary["allowed"], summary["blocked"]]
    labels = [f"Allowed ({values[0]}, {values[0] / len(records):.1%})",
              f"Blocked ({values[1]}, {values[1] / len(records):.1%})"] if records else ["Allowed (0)", "Blocked (0)"]
    ax.pie(values or [1, 0], labels=labels, colors=colors, startangle=90)
    ax.set_title(f"{title}: Allowed vs Blocked")
    ax.legend(labels, loc="best")
    _save(fig, output / "allowed_vs_blocked.png")

    attacks = summary["attacks"]
    fig, ax = plt.subplots(figsize=(7, 5))
    names = list(attacks) or ["none"]
    bars = ax.barh(names, list(attacks.values()) or [0], color="#f0a202")
    _label_bars(ax, bars)
    ax.set_title(f"{title}: Attack Types Detected")
    ax.set_xlabel("Alerts")
    _save(fig, output / "attack_types.png")

    timestamps = [datetime.fromisoformat(r["timestamp"]) for r in records if r.get("timestamp")]
    buckets = min(40, max(20, len(records) // 25)) if records else 20
    counts = {"allowed": [0] * buckets, "blocked": [0] * buckets, "alerts": [0] * buckets}
    if timestamps:
        start, end = min(timestamps), max(timestamps)
        span = max((end - start).total_seconds(), 0.001)
        for record, stamp in zip(records, timestamps):
            index = min(buckets - 1, int((stamp - start).total_seconds() / span * buckets))
            key = "allowed" if record.get("action") == "ALLOW" else "blocked"
            counts[key][index] += 1
            if record.get("alerts"):
                counts["alerts"][index] += 1
    fig, ax = plt.subplots(figsize=(8, 5))
    x = list(range(1, buckets + 1))
    ax.plot(x, counts["allowed"], color="#2ca02c", label="Allowed")
    ax.plot(x, counts["blocked"], color="#d62728", label="Blocked")
    ax.plot(x, counts["alerts"], color="#f0a202", label="Alerts")
    ax.set_title(f"{title}: Traffic Over Time")
    ax.set_xlabel("Time bucket")
    ax.set_ylabel("Packets")
    ax.legend()
    _save(fig, output / "traffic_over_time.png")

    top = summary["blocked_ips"].most_common(5)
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh([ip for ip, _ in top] or ["none"], [n for _, n in top] or [0],
                   color="#d62728")
    _label_bars(ax, bars)
    ax.set_title(f"{title}: Top 5 Attacker IPs")
    ax.set_xlabel("Blocked packets")
    _save(fig, output / "top_attacker_ips.png")

    fig, ax = plt.subplots(figsize=(5, 5))
    matrix = [[summary["tp"], summary["fn"]], [summary["fp"], summary["tn"]]]
    image = ax.imshow(matrix, cmap="YlOrRd")
    for row in range(2):
        for column in range(2):
            ax.text(column, row, matrix[row][column], ha="center", va="center")
    ax.set_xticks([0, 1], ["Blocked", "Allowed"])
    ax.set_yticks([0, 1], ["Attack", "Legitimate"])
    ax.set_title(f"{title}: Confusion Matrix")
    fig.colorbar(image, ax=ax, label="Packets")
    _save(fig, output / "confusion_matrix.png")


def generate_report(records: list[dict[str, Any]], output_dir: str | Path,
                    mode: str = "run") -> str:
    """Write a text report and five uniquely named per-mode charts."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize_records(records)
    lines = [
        "FIREWALL-BASED NETWORK SECURITY SIMULATION", "=" * 48,
        f"Mode: {mode}", f"Total packets: {summary['total']}",
        f"Allowed: {summary['allowed']}", f"Blocked: {summary['blocked']}",
        f"Alerts: {summary['alerts']}",
        f"Legitimate allowed rate: {summary['legit_allowed_rate']:.1%}",
        "",
        "Confusion matrix (TP, TN, FP, FN): "
        f"{summary['tp']}, {summary['tn']}, {summary['fp']}, {summary['fn']}",
        *[f"{key.title()}: {summary[key]:.3f}" for key in
          ("accuracy", "precision", "recall", "f1", "false_positive_rate")],
    ]
    report = "\n".join(lines) + "\n"
    (output / "report.txt").write_text(report, encoding="utf-8")
    _charts(records, output, mode)
    return report
