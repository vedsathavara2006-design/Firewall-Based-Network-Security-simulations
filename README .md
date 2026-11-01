# Stateless vs Stateful Firewall Simulation

A Python simulation that compares a **stateless** and a **stateful** firewall on identical network traffic and measures the difference with standard classification metrics.

Computer Networks mini project (Phase 1) by **Alpha Duo**: Himesh Rathod and Ved Sathavara, CSE E, UnitedWorld Institute of Technology, Karnavati University. Mentor: Ms. Pragya Vats.

## Overview

A stateless firewall judges every packet in isolation using a priority-ordered rule table. A stateful firewall also tracks a connection table and uses that context. This project runs both on the same synthetic traffic of **1,000 labelled packets** (72 attacks, 928 legitimate) spread over 40 time buckets, then compares them using TP, TN, FP, FN, accuracy, precision, recall and F1-score.

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

| Component | Role |
|---|---|
| **TrafficGenerator** | Creates 1,000 labelled packets (legitimate or attack) over 40 time buckets |
| **Packet** | Carries source IP, destination port, protocol, direction and ground-truth label |
| **Firewall** | Decision point; runs in stateless or stateful mode on the same packets |
| **RuleEngine** | Priority-ordered rule table (1 to 31); first match wins; unmatched packets hit the default block policy |
| **ConnectionTracker** | Connection table consulted in stateful mode so packets of established legitimate connections are handled correctly |
| **IDS** | Signature-based alerts for SQL injection, XSS, path traversal and brute force |
| **EventLogger** | Records every decision and alert, then produces the CSV logs, `report.txt` and PNG charts |

The rule table has eight rules covering a blacklisted IP, Telnet, FTP, SSH, ICMP, HTTP, HTTPS and DNS.

## Attacks Simulated

SQL injection, cross-site scripting (XSS), path traversal, brute force, and traffic from a blacklisted source IP.

## Results

| Metric | Stateless | Stateful |
|---|---|---|
| True Positives | 65 | 68 |
| True Negatives | 751 | 928 |
| False Positives | 177 | 0 |
| False Negatives | 7 | 4 |
| Accuracy | 81.6% | 99.6% |
| Precision | 26.9% | 100% |
| Recall | 90.3% | 94.4% |
| F1-score | 0.414 | 0.971 |

- The stateless firewall blocked 242 packets, but 177 of them were legitimate, which pulled precision down to 26.9%.
- The stateful firewall blocked only 68 packets, all genuine attacks: zero false positives.
- Recall improved from 90.3% to 94.4% (false negatives fell from 7 to 4).
- Both firewalls raised the same 28 IDS alerts (XSS 11, SQL injection 10, path traversal 6, brute force 1), showing that signature alerting is independent of state while the blocking decision improves with state tracking.

**Metric definitions:** a positive is an attack packet that gets blocked.
Accuracy = (TP+TN)/(TP+TN+FP+FN), Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1 = 2·P·R/(P+R).

## Outputs

Each run produces:

- **CSV** event logs of every packet decision
- **report.txt** with the metrics summary
- **PNG charts**: allowed vs blocked, attack types, traffic over time, top attacker IPs, confusion matrices, and stateless vs stateful comparison graphs
- A **Rich** comparison table in the terminal

## Project Structure

```text
firewall_sim/
├── main.py            # entry point
├── config/            # configuration and rule table
├── core/              # traffic generator, rule engine, tracker, IDS, firewall, logger
├── tests/             # Pytest unit tests
├── logs/              # run logs
├── output/            # generated CSV, report and charts
├── reports/           # results report
├── requirements.txt
└── README.md
```

## Getting Started

Requires Python 3.11 and the packages in `requirements.txt` (Matplotlib, Rich, Pytest).

```bash
git clone <your-repo-url>
cd firewall_sim
pip install -r requirements.txt
python main.py
pytest
```

## Scope and Future Work

This is an offline simulation and does not filter live traffic. Planned work:

- Deep packet inspection and application-layer awareness
- IDS/IPS with machine-learning anomaly detection
- Real captured traffic (PCAP) instead of synthetic data
- IPv6, NAT and VPN support
- Rate limiting and DDoS protection
- Web dashboard for monitoring and rule editing
- Latency and throughput analysis of stateful tracking

## References

1. A. S. Tanenbaum and D. J. Wetherall, *Computer Networks*, Pearson.
2. W. Stallings, *Network Security Essentials*, Pearson.
3. NIST SP 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy*.
