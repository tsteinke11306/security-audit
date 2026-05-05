# VPS Security Audit Script

A comprehensive, automated security audit tool for Ubuntu VPS environments. Scans SSH configuration, firewall status, open ports, SSL certificates, failed logins, pending updates, system resources, and user accounts — then generates clean, shareable reports.

Built by [Trevor Steinke](https://trevorsteinke.com) as a portfolio project demonstrating Python + Linux administration + security hardening skills.

---

## Features

- **SSH Hardening Audit** — Checks key-only auth, root login disabled, non-standard port
- **Firewall Validation** — Verifies UFW/firewalld status and iptables rules
- **Port & Service Scanning** — Identifies listening services and flags risky exposures
- **Authentication Monitoring** — Reviews failed login attempts from logs
- **Patch Management** — Checks for pending security updates via apt
- **SSL/TLS Certificate Health** — Monitors expiry dates for Let's Encrypt certs
- **Intrusion Prevention** — Verifies fail2ban is active
- **Resource Monitoring** — CPU load, memory usage, disk space
- **User Account Review** — Flags passwordless accounts
- **Multi-Format Reports** — JSON, Markdown (GitHub-friendly), and plain text

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/tsteinke11306/security-audit.git
cd security-audit

# Run the audit (no dependencies needed)
python3 security_audit.py

# Output: console report + 3 files in reports/
```

---

## Sample Output

```
======================================================================
  VPS SECURITY AUDIT REPORT
======================================================================
  Hostname:    your-hostname
  OS:          Ubuntu 24.04.2 LTS
  Timestamp:   2026-05-05T11:31:00
======================================================================

SUMMARY
----------------------------------------------------------------------
  Total Checks:  15
  PASS:          11
  WARN:          0
  FAIL:          1
  INFO:          3

SSH
----------------------------------------------------------------------
  [PASS] Password Authentication
           SSH key-only authentication is enabled
  [PASS] Root Login
           Root login is disabled
  [WARN] SSH Port
           SSH running on default port 22
           → Consider moving SSH to a non-standard port

FIREWALL
----------------------------------------------------------------------
  [FAIL] UFW Status
           UFW firewall is not active
           → Enable UFW: sudo ufw enable

NETWORK
----------------------------------------------------------------------
  [INFO] Listening Services
           Found 7 listening services

... (truncated)
```

---

## Project Structure

```
security-audit/
├── security_audit.py      # Main audit script
├── requirements.txt       # Dependencies (none for core, see below)
├── README.md              # This file
└── reports/               # Generated audit reports
    ├── audit_vmi3209984_20260505_113100.json
    ├── audit_vmi3209984_20260505_113100.txt
    └── audit_vmi3209984_20260505_113100.md
```

---

## Requirements

- Python 3.7+
- Ubuntu/Debian-based Linux (uses `apt`, `ss`, `journalctl`, etc.)
- Run as a user with read access to:
  - `/etc/ssh/sshd_config`
  - `/var/log/auth.log` or `journalctl`
  - `/etc/shadow` (for passwordless account checks — requires root or sudo)

No external Python packages are required for the core script.

### Optional Enhancements

```bash
pip install -r requirements.txt
```

This installs:
- `requests` — for future webhook/email alerting features
- `rich` — for prettier console output (planned)

---

## What This Demonstrates

| Skill Area | How This Project Shows It |
|------------|---------------------------|
| **Python** | Clean OOP design, type hints, subprocess handling, file parsing |
| **Linux Admin** | Deep system inspection: logs, configs, services, networking |
| **Security Mindset** | Proactive hardening checks, not reactive troubleshooting |
| **Documentation** | README, inline comments, generated Markdown reports |
| **Automation** | Script replaces manual `ss`, `ufw status`, `apt` checks |
| **Reporting** | Structured JSON + human-readable text + GitHub-friendly Markdown |

---

## Roadmap / TODO

- [ ] Add `--cron` mode for scheduled automated audits
- [ ] Email/webhook alerting on failures
- [ ] Compare current vs. previous audit (diff mode)
- [ ] CIS Benchmark alignment (scored checks)
- [ ] Docker container audit module
- [ ] Nginx/Apache config audit module
- [ ] Prettier terminal output with `rich`

---

## License

MIT — use it, fork it, improve it.

---

## Contact

- Website: [trevorsteinke.com](https://trevorsteinke.com)
- GitHub: [@tsteinke11306](https://github.com/tsteinke11306)
- LinkedIn: [trevor-steinke](https://linkedin.com/in/trevor-steinke)
