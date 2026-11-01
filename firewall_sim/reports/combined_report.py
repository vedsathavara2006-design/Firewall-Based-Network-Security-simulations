"""Self-contained, non-duplicating HTML and PDF reports."""

import base64
import csv
import json
from html import escape
from pathlib import Path
from typing import Any

from .report_generator import summarize_records

CHARTS = ("allowed_vs_blocked.png", "attack_types.png", "traffic_over_time.png",
          "top_attacker_ips.png", "confusion_matrix.png")


def _image(path: Path) -> str:
    if not path.exists():
        return ""
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f'<img src="data:image/png;base64,{encoded}" alt="{escape(path.stem)}">'


def _metrics(summary: dict[str, Any]) -> str:
    values = ("tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1",
              "false_positive_rate", "legit_allowed_rate")
    rows = "".join(f"<tr><th>{key.upper()}</th><td>{summary[key]:.3f}"
                   f"</td></tr>" if isinstance(summary[key], float)
                   else f"<tr><th>{key.upper()}</th><td>{summary[key]}</td></tr>"
                   for key in values)
    return f"<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"


def _summary_html(summary: dict[str, Any]) -> str:
    rows = "".join(f"<tr><th>{key.title()}</th><td>{summary[key]}</td></tr>"
                   for key in ("total", "allowed", "blocked", "alerts"))
    return f"<table><tbody>{rows}</tbody></table>{_metrics(summary)}"


def _rules_html(rules_path: Path) -> str:
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "<p>Rules could not be loaded.</p>"
    headers = sorted({key for rule in rules for key in rule})
    head = "".join(f"<th>{escape(key)}</th>" for key in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(rule.get(key, '')))}</td>"
                   for key in headers) + "</tr>" for rule in rules)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _log_html(output: Path) -> str:
    path = output / "firewall_log.csv"
    if not path.exists():
        return "<p>No firewall log was produced.</p>"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    headers = ["timestamp", "event_type", "src_ip", "dst_ip", "protocol", "action",
               "rule_id", "reason", "attack_type"]
    body = "".join("<tr>" + "".join(f"<td>{escape(row.get(key, ''))}</td>"
                   for key in headers) + "</tr>" for row in rows[:200])
    head = "".join(f"<th>{key}</th>" for key in headers)
    return f"<p>Showing {min(200, len(rows))} of {len(rows)} log rows.</p><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _comparison_html(comparison: dict[str, Any]) -> str:
    stateless, stateful = comparison["stateless"], comparison["stateful"]
    headers = ["Metric", "Stateless", "Stateful"]
    metrics = ("tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1")
    body = "".join(f"<tr><th>{key.upper()}</th><td>{stateless[key]}</td><td>{stateful[key]}</td></tr>"
                   for key in metrics)
    conclusion = (f"Stateful reduced false positives from {stateless['fp']} to {stateful['fp']} "
                  f"and false negatives from {stateless['fn']} to {stateful['fn']}.")
    return (f"<table><thead><tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr></thead>"
            f"<tbody>{body}</tbody></table><p>{escape(conclusion)}</p>")


def generate_final_reports(records: list[dict[str, Any]], output_dir: str | Path,
                           parameters: dict[str, Any], console_output: str,
                           rules_path: str | Path, comparison: dict[str, Any] | None = None,
                           extra_charts: list[Path] | None = None) -> tuple[Path, Path]:
    """Create one HTML/PDF report with each supplied chart rendered exactly once."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize_records(records)
    mode = str(parameters.get("mode", "run"))
    images = "".join(f"<figure>{_image(output / chart)}</figure>" for chart in CHARTS)
    if extra_charts:
        images += "".join(f"<figure>{_image(path)}</figure>" for path in extra_charts)
    comparison_section = _comparison_html(comparison) if comparison else ""
    params = "".join(f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>"
                     for key, value in parameters.items())
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Firewall Simulation Report</title>
<style>body{{font-family:Arial;max-width:1200px;margin:2em auto;line-height:1.4}}
table{{border-collapse:collapse;width:100%;margin:1em 0}}th,td{{border:1px solid #bbb;padding:6px;text-align:left}}
th{{background:#eee}}img{{max-width:100%}}figure{{display:inline-block;width:47%;vertical-align:top;margin:1%}}
pre{{background:#111;color:#eee;padding:1em;white-space:pre-wrap}}@media print{{body{{max-width:none}}}}</style>
</head><body><h1>Firewall-Based Network Security Simulation</h1>
<nav><a href="#summary">Summary</a> | <a href="#charts">Charts</a> | <a href="#rules">Rules</a> |
<a href="#console">Console</a></nav>
<h2 id="summary">{escape(mode.title())} Summary</h2>{_summary_html(summary)}
<h2 id="parameters">Run Parameters</h2><table><tbody>{params}</tbody></table>
<h2 id="charts">Charts</h2>{images}
{"<h2 id='comparison'>Comparison</h2>" + comparison_section if comparison else ""}
<h2 id="rules">Firewall Rules</h2>{_rules_html(Path(rules_path))}
<h2 id="console">Console Output</h2><pre>{escape(console_output)}</pre>
<h2 id="log">Firewall Log</h2>{_log_html(output)}</body></html>"""
    html_path = output / "final_report.html"
    html_path.write_text(html, encoding="utf-8")
    pdf_path = output / "final_report.pdf"
    _write_pdf(pdf_path, summary, parameters, console_output, output, comparison,
               extra_charts or [])
    return html_path, pdf_path


def _write_pdf(path: Path, summary: dict[str, Any], parameters: dict[str, Any],
               console_output: str, output: Path, comparison: dict[str, Any] | None,
               extra_charts: list[Path]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    with PdfPages(path) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))
        text = ["FIREWALL SIMULATION REPORT", *[f"{k}: {v}" for k, v in parameters.items()],
                "", *[f"{k}: {summary[k]}" for k in ("total", "allowed", "blocked", "alerts",
                                                       "tp", "tn", "fp", "fn")]]
        if comparison:
            text += ["", f"Stateful reduced false positives from {comparison['stateless']['fp']} "
                     f"to {comparison['stateful']['fp']}."]
        fig.text(0.06, 0.95, "\n".join(text), va="top", family="monospace", fontsize=9)
        pdf.savefig(fig); plt.close(fig)
        for chart in [output / name for name in CHARTS] + extra_charts:
            if chart.exists():
                image = plt.imread(chart)
                fig, ax = plt.subplots(figsize=(8.27, 11.69))
                ax.imshow(image); ax.axis("off"); pdf.savefig(fig); plt.close(fig)
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.text(0.06, 0.95, "CONSOLE OUTPUT\n" + console_output, va="top",
                 family="monospace", fontsize=7)
        pdf.savefig(fig); plt.close(fig)


def generate_master_report(output_dir: str | Path, stateless_dir: Path, stateful_dir: Path,
                           comparison_dir: Path, comparison: dict[str, Any],
                           rules_path: str | Path, console_output: str) -> tuple[Path, Path]:
    """Build the combined report from canonical per-mode and comparison chart paths."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    mode_charts = {name: [directory / chart for chart in CHARTS]
                   for name, directory in (("Stateless", stateless_dir), ("Stateful", stateful_dir))}
    comparison_charts = [comparison_dir / name for name in
                         ("comparison_counts.png", "comparison_confusion.png",
                          "comparison_quality.png")]
    sections = []
    for name, charts in mode_charts.items():
        sections.append(f"<h2 id='{name.lower()}'>{name} section</h2>" +
                        "".join(f"<figure>{_image(path)}</figure>" for path in charts))
    comparison_images = "".join(f"<figure>{_image(path)}</figure>" for path in comparison_charts)
    stateless, stateful = comparison["stateless"], comparison["stateful"]
    conclusion = (f"Stateful reduced false positives from {stateless['fp']} to {stateful['fp']} "
                  f"and false negatives from {stateless['fn']} to {stateful['fn']}.")
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Firewall All Results</title>
<style>body{{font-family:Arial;max-width:1200px;margin:2em auto}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #bbb;padding:6px}}th{{background:#eee}}img{{max-width:100%}}
figure{{display:inline-block;width:47%;vertical-align:top;margin:1%}}pre{{background:#111;color:#eee;padding:1em}}
@media print{{body{{max-width:none}}}}</style></head><body>
<h1>Firewall Simulation - All Results</h1>
<nav><a href="#executive">Executive summary</a> | <a href="#stateless">Stateless</a> |
<a href="#stateful">Stateful</a> | <a href="#comparison">Comparison</a> |
<a href="#rules">Rules</a> | <a href="#console">Console</a></nav>
<h2 id="executive">Executive summary and key findings</h2><p>{escape(conclusion)}</p>
{_comparison_html(comparison)}
{''.join(sections)}
<h2 id="comparison">Comparison section</h2>{comparison_images}<p>{escape(conclusion)}</p>
<h2 id="rules">Firewall rules table</h2>{_rules_html(Path(rules_path))}
<h2 id="console">Console output</h2><pre>{escape(console_output)}</pre></body></html>"""
    html_path = output / "FINAL_ALL_RESULTS.html"
    html_path.write_text(html, encoding="utf-8")
    pdf_path = output / "FINAL_ALL_RESULTS.pdf"
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    with PdfPages(pdf_path) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.text(0.06, 0.94, "EXECUTIVE SUMMARY\n" + conclusion + "\n\n"
                 + "\n".join(f"{key}: stateless={stateless[key]}, stateful={stateful[key]}"
                             for key in ("tp", "tn", "fp", "fn", "accuracy", "precision",
                                         "recall", "f1")), va="top", family="monospace")
        pdf.savefig(fig); plt.close(fig)
        for path in [path for charts in mode_charts.values() for path in charts] + comparison_charts:
            if path.exists():
                image = plt.imread(path)
                fig, ax = plt.subplots(figsize=(8.27, 11.69))
                ax.imshow(image); ax.axis("off"); pdf.savefig(fig); plt.close(fig)
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.text(0.06, 0.95, "CONSOLE OUTPUT\n" + console_output, va="top",
                 family="monospace", fontsize=7)
        pdf.savefig(fig); plt.close(fig)
    return html_path, pdf_path
