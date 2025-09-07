# Project Redeye

**Project Redeye** is a reconnaissance and asset discovery utility designed for ethical security testing.

It helps you:
1. **Enumerate subdomains** (via Amass/Sublist3r if installed, or fallback wordlist).
2. **Scan open ports/services** (via Nmap if installed, or a lightweight socket scanner).
3. **Enrich host intelligence** (via the Shodan API).

---

## 🚀 Quick Start

```bash
git clone https://github.com/yourusername/project-redeye.git
cd project-redeye
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Basic usage

```bash
python redeye.py example.com --verbose
```

### With Shodan enrichment

```bash
export SHODAN_API_KEY=your_api_key
python redeye.py example.com
```

Reports are saved to:

```
./reports/<domain>/
    ├─ report.json
    ├─ report.csv
    └─ report.md
```

---

## ⚠️ Legal Disclaimer

Project Redeye is for **educational and authorized security testing only**.
Do not use it on targets you do not own or have explicit permission to assess.
