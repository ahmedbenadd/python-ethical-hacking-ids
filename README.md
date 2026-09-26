# 🛡️ Ethical Hacking Application Suite

**Red Team attack dashboard vs. Blue Team SOC dashboard** — a self-contained lab for
launching, observing, and detecting common network attack techniques in a controlled
environment.

> **Academic project.** Built for learning offensive/defensive concepts. Run it only on
networks and machines you own or have explicit written permission to test. The apps bind
to `0.0.0.0` so the two sides can talk to each other on your LAN — do **not** expose them
to the internet or a network you do not own.

---

## Architecture

Two fully independent Flask applications that attack and defend each other:

```
python-ethical-hacking/
├── attacker_app/          # 🔴 Red Team — Attack Dashboard (port 5000)
│   ├── app.py             # Flask + SocketIO entry point
│   ├── modules/           # Attack modules (scanner, brute forcer, ARP spoofer, discovery)
│   ├── routes/            # REST blueprints
│   ├── templates/         # Jinja2 pages
│   └── requirements.txt
├── victim_app/            # 🔵 Blue Team — SOC / IDS Dashboard (port 5001)
│   ├── app.py             # Flask + SocketIO entry point
│   ├── core/              # Sniffer, IDS analyzer, traffic monitor
│   ├── templates/         # Jinja2 SOC dashboard
│   └── requirements.txt
└── HOW_TO_START.txt
```

Each app has its own `requirements.txt` and its own virtual environment.

---

## 🔴 Attacker App — Attack Dashboard

| Module | Endpoint | Description |
|--------|----------|-------------|
| Nmap Scanner | `POST /api/attack/scanner` | 8 scan profiles (Quick, Full, Service, OS, Aggressive, Stealth, UDP, Vuln) via `python-nmap` |
| Brute Force | `POST /api/attack/bruteforce` | Credential-stuffing simulator against an HTTP login form, with a built-in demo wordlist and live attempt feed |
| ARP Spoof | `POST /api/attack/arp` | ARP cache poisoning (MITM) via Scapy, enables IP forwarding while active |
| Network Discovery | `POST /api/network/discover` | Host enumeration and ARP-table mapping of a target subnet |
| Status | `GET /api/status` | Active-attack state for the dashboard |

Attacks execute in background threads and stream progress to the browser over SocketIO, so
the UI stays responsive during long scans.

## 🔵 Victim App — SOC / IDS Dashboard

Live packet capture with real-time rule-based detection:

- **IDS engine** — `ARP poisoning`, `SSH brute force`, `Nmap scan`, `web scanner`, and
  `HTTP brute force` detection
- **Sliding-window thresholds** — e.g. brute force trips at 5 failed attempts in a 20s
  window; port scanning trips at 15 distinct ports
- **Live alert feed** — SocketIO push of every alert, plus packet-level visualisation
- **ARP anomaly tracking** — flags an IP whose MAC changes without the table being drained

---

## Quick Start

Requires Python 3.8+ and `sudo` (raw sockets for Scapy, and Nmap itself).

### 🔴 Attacker App

```bash
cd attacker_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo ./venv/bin/python3 app.py
```

→ http://localhost:5000

### 🔵 Victim App

```bash
cd victim_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo ./venv/bin/python3 app.py            # all interfaces
sudo ./venv/bin/python3 app.py -i eth0    # single interface
```

→ http://localhost:5001

### Dependencies

| App | Packages |
|-----|----------|
| Attacker | Flask, Flask-SocketIO, Flask-CORS, Eventlet, python-nmap, Scapy, Requests, Paramiko |
| Victim | Flask, Flask-SocketIO, Eventlet, Scapy, NetworkX |

---

## Security Notes

- `SECRET_KEY` is read from the environment via `os.environ.get(...)` with a
  dev-only fallback. Set your own in a local `.env` (git-ignored) if you run this anywhere
  other than your own machine — the fallback value is intentionally not a real secret.
- CORS is wide open (`origins: "*"`) because both sides are local lab services. Lock this
  down before doing anything else if you deploy.
- Packet captures and scan output (`*.pcap`, `*.txt`) are git-ignored so real captured
  traffic never lands in a public repository.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Intended strictly for educational use in a self-contained lab. The author accepts no
liability for misuse. Do not run the attack modules against third-party systems without
prior written authorization.
