"""Focused tests for ACLs, stateful inspection, IDS detectors, and expiry."""

from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import sys

from core.connection_tracker import ConnectionTracker
from core.ids import IntrusionDetector
from core.packet import Packet
from core.rule_engine import Rule, RuleEngine
from core.traffic_generator import TrafficGenerator
from reports.comparison import compare_records
from reports.combined_report import generate_final_reports
from reports.report_generator import generate_report
from core.firewall import Firewall
import json


NOW = datetime(2026, 1, 1)


def packet(src="198.51.100.1", dst_port=80, protocol="TCP", flags=frozenset({"SYN"}),
           payload=""):
    return Packet(NOW, src, "10.0.0.10", 50000, dst_port, protocol, flags, 100, payload)


def detector(**overrides):
    settings = {
        "port_scan_unique_ports": 3, "port_scan_window_seconds": 10,
        "syn_flood_threshold": 3, "syn_flood_window_seconds": 10,
        "icmp_flood_threshold": 3, "icmp_flood_window_seconds": 10,
        "brute_force_threshold": 3, "brute_force_window_seconds": 20,
        "rate_limit_packets": 100, "rate_limit_window_seconds": 10,
        "blacklist_violation_threshold": 99, "blacklist_duration_seconds": 2,
    }
    settings.update(overrides)
    return IntrusionDetector(settings)


def test_rule_matching_cidr_and_port_range():
    rule = Rule.from_dict({"id": "r", "priority": 1, "action": "ALLOW",
                           "src_ip": "10.0.0.0/24", "dst_port": "8000-8100"})
    assert rule.matches(packet("10.0.0.7", 8050))
    assert not rule.matches(packet("10.0.1.7", 8050))
    assert not rule.matches(packet("10.0.0.7", 9000))


def test_first_match_priority_and_default_policy():
    engine = RuleEngine([
        Rule.from_dict({"id": "deny", "priority": 1, "action": "DENY", "dst_port": 23}),
        Rule.from_dict({"id": "allow", "priority": 2, "action": "ALLOW"}),
    ])
    assert engine.evaluate(packet(dst_port=23))[0] == "DENY"
    assert engine.evaluate(packet(dst_port=9999))[0] == "ALLOW"
    assert RuleEngine([], "DENY").evaluate(packet(dst_port=9999))[0] == "DENY"


def test_state_tracking_allows_established_return_traffic():
    tracker = ConnectionTracker()
    outbound = packet("10.0.0.20", 80, flags=frozenset({"SYN"}))
    assert tracker.inspect(outbound)[0]
    reply = Packet(NOW, "10.0.0.10", "10.0.0.20", 80, 50000, "TCP",
                   frozenset({"SYN", "ACK"}), 100, "", "OUTBOUND")
    assert tracker.inspect(reply)[0]
    assert tracker.connections[outbound.five_tuple].state == "ESTABLISHED"


def test_port_scan_detector():
    ids = detector()
    alerts = [a for port in [1, 2, 3] for a in ids.inspect(packet(dst_port=port))]
    assert any(a.attack_type == "port_scan" for a in alerts)


def test_syn_flood_detector():
    ids = detector()
    alerts = [a for _ in range(3) for a in ids.inspect(packet(dst_port=1000))]
    assert any(a.attack_type == "syn_flood" for a in alerts)


def test_icmp_flood_detector():
    ids = detector()
    alerts = [a for _ in range(3) for a in ids.inspect(packet(dst_port=None, protocol="ICMP", flags=frozenset()))]
    assert any(a.attack_type == "icmp_flood" for a in alerts)


def test_brute_force_and_payload_detectors():
    ids = detector()
    alerts = [a for _ in range(3) for a in ids.inspect(packet(dst_port=22))]
    alerts += ids.inspect(packet(payload="DROP TABLE users"))
    assert any(a.attack_type == "brute_force" for a in alerts)
    assert any(a.attack_type == "sql_injection" for a in alerts)


def test_blacklist_expiry():
    ids = detector(blacklist_violation_threshold=1, blacklist_duration_seconds=2)
    ids.inspect(packet(payload="<script>"))
    assert ids.is_blacklisted("198.51.100.1", NOW)
    assert not ids.is_blacklisted("198.51.100.1", NOW + timedelta(seconds=3))


def test_same_seed_generates_identical_traffic():
    left = list(TrafficGenerator(42).packets(20, 0.3))
    right = list(TrafficGenerator(42).packets(20, 0.3))
    assert left == right


def test_comparison_returns_both_modes_results():
    records = [{"action": "ALLOW", "src_ip": "10.0.0.1", "rule_id": "r",
                "alerts": []}]
    result = compare_records(records, records)
    assert {row["mode"] for row in result["rows"]} == {"stateless", "stateful"}
    assert "stateless" in result and "stateful" in result


def test_output_dir_creation_and_report_files(tmp_path):
    project = Path(__file__).parents[1]
    target = tmp_path / "nested" / "run"
    subprocess.run([sys.executable, "main.py", "--packets", "2", "--seed", "1",
                    "--output-dir", str(target)], cwd=project, check=True,
                   capture_output=True, text=True)
    assert target.is_dir()


def test_report_files_are_created(tmp_path):
    project = Path(__file__).parents[1]
    target = tmp_path / "reports"
    subprocess.run([sys.executable, "main.py", "--packets", "2", "--seed", "1",
                    "--output-dir", str(target)], cwd=project, check=True,
                   capture_output=True, text=True)
    assert (target / "firewall_log.csv").exists()
    assert (target / "report.txt").exists()
    assert (target / "allowed_vs_blocked.png").exists()


def test_final_report_html_has_embedded_images(tmp_path):
    output = tmp_path / "report"
    records = [{"action": "ALLOW", "src_ip": "10.0.0.1", "rule_id": "r",
                "alerts": [], "timestamp": NOW.isoformat(), "event_type": "PACKET",
                "dst_ip": "10.0.0.10", "protocol": "TCP", "src_port": 1,
                "dst_port": 80, "reason": "test", "attack_type": ""}]
    generate_report(records, output)
    html, _ = generate_final_reports(records, output, {"mode": "stateful"},
                                     "test output", Path(__file__).parents[1] / "config" / "rules.json")
    content = html.read_text(encoding="utf-8")
    assert html.stat().st_size > 0
    assert content.count("data:image/png;base64,") >= 4


def test_final_report_pdf_is_valid(tmp_path):
    output = tmp_path / "pdf"
    records = [{"action": "ALLOW", "src_ip": "10.0.0.1", "rule_id": "r",
                "alerts": [], "timestamp": NOW.isoformat(), "event_type": "PACKET",
                "dst_ip": "10.0.0.10", "protocol": "TCP", "src_port": 1,
                "dst_port": 80, "reason": "test", "attack_type": ""}]
    generate_report(records, output)
    _, pdf = generate_final_reports(records, output, {"mode": "stateful"},
                                    "test output", Path(__file__).parents[1] / "config" / "rules.json")
    assert pdf.stat().st_size > 0
    assert pdf.read_bytes().startswith(b"%PDF")


def _comparison_firewalls():
    root = Path(__file__).parents[1]
    settings = json.loads((root / "config" / "settings.json").read_text(encoding="utf-8"))
    engine = RuleEngine.from_json(root / "config" / "rules.json", settings["default_policy"])
    packets = list(TrafficGenerator(42).packets(300, 0.3))
    results = []
    for stateful in (False, True):
        firewall = Firewall(engine, IntrusionDetector(settings["ids"]),
                            ConnectionTracker(settings["connection_timeout_seconds"]),
                            stateful=stateful)
        firewall.process_all(packets)
        results.append(firewall.records)
    return results


def test_stateful_and_stateless_differ_and_stateful_reduces_false_positives():
    from reports.report_generator import summarize_records
    stateless, stateful = (_comparison_firewalls())
    left, right = summarize_records(stateless), summarize_records(stateful)
    assert left != right
    assert right["fp"] <= left["fp"]
    assert right["legit_allowed_rate"] > 0.9


def test_internal_ips_are_not_blacklisted_without_attack():
    ids = detector(rate_limit_packets=1, blacklist_violation_threshold=1)
    for index in range(10):
        ids.inspect(Packet(NOW + timedelta(milliseconds=index), "10.0.0.20",
                           "10.0.0.10", 40000 + index, 80, "TCP",
                           frozenset({"SYN"}), 100))
    assert not ids.is_blacklisted("10.0.0.20", NOW + timedelta(seconds=1))


def test_each_chart_has_unique_file_and_html_embeds_each_once(tmp_path):
    output = tmp_path / "charts"
    records = list(TrafficGenerator(7).packets(40, 0.3))
    firewall = Firewall(RuleEngine([], "ALLOW"), detector(), ConnectionTracker(), stateful=True)
    firewall.process_all(records)
    generate_report(firewall.records, output, "stateful")
    chart_names = ["allowed_vs_blocked.png", "attack_types.png", "traffic_over_time.png",
                   "top_attacker_ips.png", "confusion_matrix.png"]
    assert len(chart_names) == len(set(chart_names))
    assert all((output / name).exists() for name in chart_names)
    html, _ = generate_final_reports(firewall.records, output, {"mode": "stateful"},
                                     "", Path(__file__).parents[1] / "config" / "rules.json")
    assert html.read_text(encoding="utf-8").count("data:image/png;base64,") == len(chart_names)
