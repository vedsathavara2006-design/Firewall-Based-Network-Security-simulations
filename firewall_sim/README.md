# Firewall-Based Network Security Simulation

This course project simulates packet inspection without sockets, root privileges, packet capture, or real network access. It demonstrates ACLs, stateful TCP inspection, IDS thresholds, temporary blacklisting, audit logging, and reporting.

## Architecture

```text
TrafficGenerator -> Packet -> Firewall
                              |
                +-------------+-------------+
                |             |             |
             IDS alerts   ConnectionTracker  RuleEngine
                |             |             |
                +-------------+-------------+
                              |
                         EventLogger
                              |
                   CSV + report.txt + PNG charts
```

## Installation and execution

```text
cd firewall_sim
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
pytest -q
python main.py --packets 1000 --attack-ratio 0.3 --seed 42 --mode stateful
python main.py --demo --seed 42
python main.py --packets 100 --attack-ratio 0.2 --seed 7 --mode stateless --live
```

The run creates `logs/firewall_log.csv`, `output/report.txt`, and five per-mode PNG files:
allowed/blocked, attack types, bucketed traffic over time, attacker IPs, and a confusion
matrix. Charts use green for allowed traffic, red for blocked traffic, and orange for alerts.

## How to run: Stateful, Stateless, Live and Compare

Each normal run receives its own timestamped output folder. Use `--output-dir` to choose one explicitly:

```text
python main.py --packets 1000 --attack-ratio 0.3 --seed 42 --mode stateful --output-dir output/stateful
python main.py --packets 1000 --attack-ratio 0.3 --seed 42 --mode stateless --output-dir output/stateless
python main.py --packets 50 --attack-ratio 0.3 --seed 42 --live --delay 0.2
python main.py --demo
python main.py --compare --packets 1000 --attack-ratio 0.3 --seed 42 --open
```

`--compare` generates identical traffic once, runs both modes, and writes mode results,
`output/comparison/comparison_report.txt`, `comparison.csv`, three comparison charts, and
master `output/FINAL_ALL_RESULTS.html` and `output/FINAL_ALL_RESULTS.pdf`. Single-file
reports are enabled by default; use `--no-single-file` to disable them. The HTML report is
self-contained and print-friendly, while the PDF uses matplotlib `PdfPages`.

## How the firewall works

1. The generator produces timestamped synthetic TCP, UDP, and ICMP packets.
2. The IDS checks payload signatures and sliding-window thresholds for scans, floods, brute force, and rate abuse. Repeated violations create a temporary blacklist. All thresholds and ban settings (`port_scan_unique_ports`, `port_scan_window_seconds`, `syn_flood_threshold`, `icmp_flood_threshold`, `brute_force_threshold`, `rate_limit_packets`, `blacklist_violation_threshold`, and their windows/duration) are configured in `config/settings.json`. Internal 10.0.0.0/8 and 192.168.0.0/16 sources are exempt from rate-limit and scan false positives unless a real signature/attack pattern is detected.
3. Stateful mode maintains TCP five-tuples and accepts return traffic for an established connection. Expired state is removed.
4. The rule engine sorts ACL rules by priority and applies first-match-wins. If no rule matches, `default_policy` is used.
5. Every packet and alert is written to CSV, then the report module computes summaries and charts.

## Adding rules

Edit `config/rules.json`. Use `id`, numeric `priority`, `action` (`ALLOW`, `DENY`, `DROP`, or `LOG`), optional `protocol`, CIDR `src_ip`/`dst_ip`, integer or `"start-end"` ports, optional `direction`, and `description`. Lower priorities are evaluated first. The default policy is configured in `config/settings.json`.

## Screenshots

Run the demo and open `output/allowed_vs_blocked.png`, `output/attack_types.png`, `output/traffic_over_time.png`, and `output/top_attacker_ips.png` in any image viewer.

## Viva questions and answers

1. **What is a firewall?** A policy enforcement point that permits or rejects traffic using packet attributes.
2. **Why use CIDR?** CIDR represents an address and network prefix, allowing efficient subnet matching.
3. **What is first-match-wins?** Rules are checked in priority order; the first matching rule decides the action.
4. **Why is stateful inspection useful?** It understands connection context and can allow legitimate return traffic.
5. **What is a five-tuple?** Source/destination IP, source/destination port, and protocol.
6. **What is a SYN flood?** Many TCP connection-start requests that consume connection resources.
7. **How does a port scan differ from normal browsing?** A scanner contacts many destination ports in a short time.
8. **Why use a sliding window?** It detects bursts while allowing old events to expire naturally.
9. **What is temporary blacklisting?** A source is denied for a configured interval after repeated violations, then automatically expires.
10. **Why is this safe to run?** It generates objects in memory and performs no packet capture, socket operation, or privileged action.

11. **Stateful versus stateless: what is the difference?** Stateless mode evaluates each packet independently; stateful mode also consults a TCP connection table and recognizes return traffic.
12. **Why does the same seed matter in compare mode?** It makes both modes process the exact same packet sequence, so differences are attributable to firewall state handling rather than different traffic.
13. **Why use a default-deny policy?** Unknown traffic is rejected unless an explicit rule grants access, which reduces accidental exposure.
14. **Why use a sliding window?** It measures recent activity, allowing old events to expire while detecting bursts such as scans and floods.
15. **How does auto-blacklisting work?** The IDS counts violations per source and temporarily denies that IP after the configured threshold; the ban expires automatically.
