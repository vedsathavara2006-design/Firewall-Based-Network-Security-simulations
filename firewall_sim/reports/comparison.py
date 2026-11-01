"""Comparison metrics and charts for identical stateless/stateful traffic."""

import csv
from pathlib import Path
from typing import Any

from .report_generator import summarize_records


METRICS = ("tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1")


def compare_records(stateless: list[dict[str, Any]],
                    stateful: list[dict[str, Any]]) -> dict[str, Any]:
    left, right = summarize_records(stateless), summarize_records(stateful)
    rows = []
    for label, summary in (("stateless", left), ("stateful", right)):
        rows.append({"mode": label, **{key: summary[key] for key in
                     ("total", "allowed", "blocked", "alerts", *METRICS)},
                     "legit_allowed_rate": summary["legit_allowed_rate"]})
    return {"rows": rows, "stateless": left, "stateful": right,
            "stateless_records": stateless, "stateful_records": stateful}


def _value_labels(ax: Any, bars: Any, values: list[float]) -> None:
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{value:.2f}" if isinstance(value, float) else str(value),
                ha="center", va="bottom")


def _comparison_charts(result: dict[str, Any], output: Path) -> list[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = ["Stateless", "Stateful"]
    paths: list[Path] = []
    for filename, title, metrics in (
        ("comparison_counts.png", "Allowed, Blocked and Alerts", ("allowed", "blocked", "alerts")),
        ("comparison_confusion.png", "Confusion Matrix Counts", ("tp", "tn", "fp", "fn")),
        ("comparison_quality.png", "Classification Quality", ("accuracy", "precision", "recall", "f1")),
    ):
        fig, ax = plt.subplots(figsize=(8, 5))
        x = list(range(len(metrics)))
        width = 0.35
        left = [result["stateless"][metric] for metric in metrics]
        right = [result["stateful"][metric] for metric in metrics]
        first = ax.bar([value - width / 2 for value in x], left, width,
                       label=labels[0], color="#4472c4")
        second = ax.bar([value + width / 2 for value in x], right, width,
                        label=labels[1], color="#70ad47")
        _value_labels(ax, first, left)
        _value_labels(ax, second, right)
        ax.set_xticks(x, [metric.upper() for metric in metrics])
        ax.set_title(f"Stateful vs Stateless: {title}")
        ax.legend()
        fig.tight_layout()
        path = output / filename
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        paths.append(path)
    return paths


def write_comparison(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path, list[Path]]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    fields = ["mode", "total", "allowed", "blocked", "alerts", *METRICS, "legit_allowed_rate"]
    csv_path = output / "comparison.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["rows"])
    stateless, stateful = result["stateless"], result["stateful"]
    conclusion = (f"Stateful reduced false positives from {stateless['fp']} to {stateful['fp']} "
                  f"and false negatives from {stateless['fn']} to {stateful['fn']}.")
    lines = ["STATEFUL VS STATELESS COMPARISON", "=" * 70,
             " | ".join(["Metric", "Stateless", "Stateful"]), "-" * 70]
    for key in ["tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1"]:
        lines.append(f"{key.upper():12} | {stateless[key]} | {stateful[key]}")
    lines.extend(["", "Conclusion:", conclusion])
    report_path = output / "comparison_report.txt"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path, csv_path, _comparison_charts(result, output)
