"""CLI entry point for the simulated firewall."""

import argparse
import json
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from core.connection_tracker import ConnectionTracker
from core.firewall import Firewall
from core.ids import IntrusionDetector
from core.logger import EventLogger
from core.rule_engine import RuleEngine
from core.traffic_generator import TrafficGenerator
from reports.combined_report import generate_final_reports, generate_master_report
from reports.comparison import compare_records, write_comparison
from reports.report_generator import generate_report, summarize_records


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Firewall-based network security simulation")
    parser.add_argument("--packets", type=int, default=100)
    parser.add_argument("--attack-ratio", type=float, default=0.3)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--mode", choices=["stateless", "stateful"], default="stateful")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--single-file", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--open", action="store_true", dest="open_report")
    return parser


def _validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.packets < 0:
        parser.error("--packets must be non-negative")
    if not 0 <= args.attack_ratio <= 1:
        parser.error("--attack-ratio must be between 0 and 1")
    if args.delay < 0:
        parser.error("--delay must be non-negative")
    if args.compare and args.live:
        parser.error("--compare and --live cannot be combined")


def _default_output(root: Path, mode: str) -> Path:
    """Return a timestamped directory that will not overwrite a prior run."""
    base = root / "output" / f"{mode}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    candidate, index = base, 1
    while candidate.exists():
        candidate = Path(f"{base}_{index}")
        index += 1
    return candidate


def _settings(root: Path) -> tuple[dict[str, Any], RuleEngine]:
    try:
        settings = json.loads((root / "config" / "settings.json").read_text(encoding="utf-8"))
        engine = RuleEngine.from_json(root / "config" / "rules.json", settings["default_policy"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load simulation configuration: {exc}") from exc
    return settings, engine


def _run(packets: list[Any], mode: str, output: Path, settings: dict[str, Any],
         engine: RuleEngine, console: Console | None = None, live: bool = False,
         delay: float = 0.0) -> Firewall:
    logger = EventLogger(output / "firewall_log.csv", console=console, live=live)
    firewall = Firewall(engine, IntrusionDetector(settings["ids"]),
                        ConnectionTracker(settings["connection_timeout_seconds"]), logger,
                        stateful=mode == "stateful")
    try:
        for packet in packets:
            firewall.process(packet)
            if live:
                time.sleep(delay)
    except KeyboardInterrupt:
        if console:
            console.print("[yellow]Interrupted: finalizing processed packets.[/yellow]")
    finally:
        firewall.close()
    generate_report(firewall.records, output, mode)
    return firewall


def _print_summary(console: Console, summary: dict[str, Any], title: str) -> None:
    table = Table(title=title)
    table.add_column("Metric")
    table.add_column("Value")
    for key in ("total", "allowed", "blocked", "alerts"):
        style = "green" if key == "allowed" else "red" if key == "blocked" else "yellow" if key == "alerts" else None
        table.add_row(key.title(), str(summary[key]), style=style)
    console.print(table)


def _run_compare(root: Path, args: argparse.Namespace, settings: dict[str, Any],
                 engine: RuleEngine, console: Console) -> list[Path]:
    generator = TrafficGenerator(args.seed)
    packets = list(generator.demo() if args.demo else generator.packets(args.packets, args.attack_ratio))
    stateless_dir, stateful_dir, comparison_dir = root / "output" / "stateless", root / "output" / "stateful", root / "output" / "comparison"
    stateless = _run(packets, "stateless", stateless_dir, settings, engine)
    stateful = _run(packets, "stateful", stateful_dir, settings, engine)
    result = compare_records(stateless.records, stateful.records)
    _, _, charts = write_comparison(result, comparison_dir)
    if args.single_file:
        mode_parameters = vars(args).copy()
        for mode, firewall, folder in (("stateless", stateless, stateless_dir),
                                       ("stateful", stateful, stateful_dir)):
            mode_parameters["mode"] = mode
            mode_console = f"Comparison run: {mode}\n"
            generate_final_reports(firewall.records, folder, mode_parameters, mode_console,
                                   root / "config" / "rules.json")
    console.print("[bold]Stateful vs Stateless comparison[/bold]")
    table = Table()
    for column in ("mode", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1"):
        table.add_column(column.title())
    for row in result["rows"]:
        table.add_row(row["mode"], *(f"{row[key]:.3f}" if isinstance(row[key], float)
                      else str(row[key]) for key in ("tp", "tn", "fp", "fn",
                                                     "accuracy", "precision", "recall", "f1")))
    console.print(table)
    if args.single_file:
        parameters = vars(args).copy()
        parameters["mode"] = "comparison"
        comparison_console = console.export_text()
        generate_final_reports(stateful.records, comparison_dir, parameters, comparison_console,
                               root / "config" / "rules.json", result, charts)
        extra = [stateful_dir / name for name in (
            "allowed_vs_blocked.png", "attack_types.png", "traffic_over_time.png", "top_attacker_ips.png"
        )] + charts
        master_html, master_pdf = generate_master_report(
            root / "output", stateless_dir, stateful_dir, comparison_dir, result,
            root / "config" / "rules.json", comparison_console)
        paths = [root / "output" / "FINAL_ALL_RESULTS.html", root / "output" / "FINAL_ALL_RESULTS.pdf"]
        console.print(f"Single report saved: {paths[0].resolve()}")
        console.print(f"Single report saved: {paths[1].resolve()}")
        if args.open_report:
            webbrowser.open(paths[0].resolve().as_uri())
        return paths
    return [comparison_dir / "comparison_report.txt", comparison_dir / "comparison.csv", *charts]


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    _validate(args, parser)
    root = Path(__file__).parent
    settings, engine = _settings(root)
    console = Console(record=True, width=160)
    if args.compare:
        _run_compare(root, args, settings, engine, console)
        return
    if args.output_dir:
        output = Path(args.output_dir)
        if not output.is_absolute():
            output = root / output
    else:
        output = _default_output(root, args.mode)
    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"Cannot create output directory {output}: {exc}")
    packets = list(TrafficGenerator(args.seed).demo() if args.demo
                   else TrafficGenerator(args.seed).packets(args.packets, args.attack_ratio))
    firewall = _run(packets, args.mode, output, settings, engine, console, args.live, args.delay)
    summary = summarize_records(firewall.records)
    _print_summary(console, summary, f"{args.mode.title()} firewall summary")
    console.print(f"Output folder: {output.resolve()}")
    if args.single_file:
        params = vars(args).copy()
        html_path, pdf_path = generate_final_reports(
            firewall.records, output, params, console.export_text(),
            root / "config" / "rules.json")
        console.print(f"Single report saved: {html_path.resolve()}")
        console.print(f"Single report saved: {pdf_path.resolve()}")
        if args.open_report:
            webbrowser.open(html_path.resolve().as_uri())


if __name__ == "__main__":
    main()
