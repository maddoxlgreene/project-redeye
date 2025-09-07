#!/usr/bin/env python3
"""
Subdomain Enumeration & Asset Discovery

- Enumerates subdomains (prefers amass / sublist3r if installed; otherwise falls back).
- Scans for open ports/services (prefers nmap; otherwise a basic TCP connect scan on common ports).
- Optionally enriches IPs via the Shodan API.

Usage:
    python recon.py example.com --verbose
    SHODAN_API_KEY=your_key python recon.py example.com
    python recon.py example.com --shodan-key your_key --out reports

Note:
    Only assess systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    import requests  # pip install requests
except Exception:
    print("This tool requires 'requests'. Install with: pip install requests")
    raise

LOG = logging.getLogger("recon")


# ---------------------------- Data Models ---------------------------------- #

@dataclass
class PortService:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class HostFinding:
    hostname: str
    ips: List[str] = field(default_factory=list)
    ports: List[PortService] = field(default_factory=list)
    shodan: Dict[str, object] = field(default_factory=dict)


@dataclass
class RunMetadata:
    domain: str
    started_at: str
    tool_versions: Dict[str, str]
    notes: str = "Only assess systems you are authorized to test."


@dataclass
class ReconReport:
    meta: RunMetadata
    hosts: List[HostFinding]


# ---------------------------- Helpers -------------------------------------- #

def which(exe: str) -> Optional[str]:
    return shutil.which(exe)


def run(cmd: List[str], timeout: int = 120, capture: bool = True) -> Tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr)."""
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def safe_resolve(host: str) -> List[str]:
    """Resolve A/AAAA records; return a sorted list of IPs. Ignore temporary failures."""
    ips: Set[str] = set()
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                continue
    except socket.gaierror:
        pass
    return sorted(ips)


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def detect_versions() -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for tool in ("amass", "sublist3r", "nmap"):
        path = which(tool)
        if not path:
            versions[tool] = "not found"
            continue
        try:
            if tool == "amass":
                _, out, _ = run([path, "version"])
                versions[tool] = out.strip() or "unknown"
            elif tool == "sublist3r":
                versions[tool] = "installed"
            elif tool == "nmap":
                _, out, _ = run([path, "-V"])
                m = re.search(r"version\s+([0-9][^\s\n]+)", out, re.I)
                versions[tool] = m.group(1) if m else "installed"
        except Exception:
            versions[tool] = "installed"
    return versions


# ---------------------------- Enumeration ---------------------------------- #

def enumerate_subdomains(domain: str) -> Set[str]:
    subs: Set[str] = set()

    # 1) amass (preferred)
    if which("amass"):
        LOG.info("Enumerating with amass…")
        rc, out, err = run(
            ["amass", "enum", "-d", domain, "-nolocaldb", "-norecursive", "-passive"],
            timeout=600,
        )
        if rc == 0:
            for line in out.splitlines():
                s = line.strip()
                if s.endswith("." + domain) or s == domain:
                    subs.add(s.lower())
        else:
            LOG.warning("amass returned non-zero exit (%s): %s", rc, err.strip())

    # 2) sublist3r
    if which("sublist3r"):
        LOG.info("Enumerating with sublist3r…")
        out_file = Path(".sublist3r.tmp.txt")
        rc, _, err = run(["sublist3r", "-d", domain, "-o", str(out_file)], timeout=600)
        if rc == 0 and out_file.exists():
            subs.update({line.strip().lower() for line in out_file.read_text().splitlines() if line.strip()})
            out_file.unlink(missing_ok=True)
        else:
            LOG.warning("sublist3r failed: %s", err.strip())

    # 3) fallback (no external tools) — try a small common-prefix wordlist
    if not subs:
        LOG.info("No external enum tools found; using fallback wordlist.")
        prefixes = [
            "www", "api", "dev", "staging", "test", "vpn", "mail", "portal", "admin",
            "app", "assets", "cdn", "docs", "help", "support"
        ]
        for p in prefixes:
            host = f"{p}.{domain}"
            if safe_resolve(host):
                subs.add(host)

    # Include root if it resolves
    if safe_resolve(domain):
        subs.add(domain)

    LOG.info("Found %d unique hostnames.", len(subs))
    return subs


# ---------------------------- Port Scanning -------------------------------- #

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 593, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2082, 2083, 2483,
    2484, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4040, 4444, 4567, 5000,
    5044, 5060, 5432, 5601, 5672, 5900, 5985, 5986, 6000, 6379, 6666, 7001,
    7002, 7007, 7077, 7200, 7474, 8000, 8008, 8080, 8081, 8088, 8123, 8443,
    8500, 8530, 8531, 9000, 9200, 9300, 9418, 11211, 15672, 27017, 27018
]

def nmap_scan(target: str) -> List[PortService]:
    """Prefer nmap; otherwise return [] to allow fallback to handle it."""
    path = which("nmap")
    if not path:
        return fallback_socket_scan(target, COMMON_PORTS)

    args = [path, "-Pn", "-sS", "-sV", "-T4", "--version-light", target]
    rc, out, err = run(args, timeout=600)
    if rc != 0:
        LOG.warning("nmap failed on %s: %s", target, err.strip())
        return []

    ports: List[PortService] = []
    for line in out.splitlines():
        # Typical line: "80/tcp open  http Apache httpd 2.4.41"
        m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$", line.strip())
        if not m:
            continue
        port, proto, state, service, rest = m.groups()
        product, version = None, None
        if rest:
            parts = rest.split()
            if parts:
                product = " ".join(parts)
        ports.append(
            PortService(
                port=int(port),
                protocol=proto,
                state=state,
                service=service if service != "unknown" else None,
                product=product,
                version=version,
            )
        )
    return ports


def fallback_socket_scan(host: str, ports: Iterable[int]) -> List[PortService]:
    """Very simple TCP connect scan for environments without nmap."""
    LOG.info("nmap not found; using basic TCP connect scan on a common-port set.")
    results: List[PortService] = []
    ips = safe_resolve(host)
    if not ips:
        return results

    ip = ips[0]
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=1.0):
                results.append(PortService(port=p, protocol="tcp", state="open"))
        except Exception:
            continue
    return results


# ---------------------------- Shodan --------------------------------------- #

def shodan_lookup(ip: str, api_key: Optional[str]) -> Dict[str, object]:
    if not api_key:
        return {}
    try:
        resp = requests.get(
            "https://api.shodan.io/shodan/host/" + ip,
            params={"key": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip_str": data.get("ip_str"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country_name": data.get("country_name"),
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
                "vulns": sorted(list(data.get("vulns", {}).keys())) if isinstance(data.get("vulns"), dict) else [],
            }
        LOG.warning("Shodan returned %s for %s", resp.status_code, ip)
    except requests.RequestException as exc:
        LOG.warning("Shodan lookup failed for %s: %s", ip, exc)
    return {}


# ---------------------------- Reporting ------------------------------------ #

def write_reports(report: ReconReport, out_dir: Path) -> None:
    ensure_dir(out_dir)

    # JSON
    json_path = out_dir / "report.json"
    with json_path.open("w") as f:
        json.dump(
            {"meta": asdict(report.meta), "hosts": [asdict(h) for h in report.hosts]},
            f,
            indent=2,
        )

    # CSV (flat)
    csv_path = out_dir / "report.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "ip", "port", "protocol", "state", "service", "product"])
        for h in report.hosts:
            ip_list = h.ips or [""]
            for ip in ip_list:
                if h.ports:
                    for ps in h.ports:
                        writer.writerow([h.hostname, ip, ps.port, ps.protocol, ps.state, ps.service or "", ps.product or ""])
                else:
                    writer.writerow([h.hostname, ip, "", "", "", "", ""])

    # Markdown (human-readable)
    md_path = out_dir / "report.md"
    with md_path.open("w") as f:
        f.write(f"# Recon Report for `{report.meta.domain}`\n\n")
        f.write(f"- Generated: {report.meta.started_at}\n")
        f.write(f"- Tools: {json.dumps(report.meta.tool_versions)}\n")
        f.write(f"- Note: {report.meta.notes}\n\n")
        for h in report.hosts:
            f.write(f"## {h.hostname}\n\n")
            f.write(f"- IPs: {', '.join(h.ips) if h.ips else 'unresolved'}\n")
            if h.ports:
                f.write("\n| Port | Proto | State | Service | Product |\n|---:|:---:|:---:|:---|:---|\n")
                for ps in h.ports:
                    f.write(f"| {ps.port} | {ps.protocol} | {ps.state} | {ps.service or ''} | {ps.product or ''} |\n")
            else:
                f.write("\n_No open ports discovered (with current method/set)._\n")
            if h.shodan:
                f.write("\n**Shodan**\n\n")
                f.write("```json\n" + json.dumps(h.shodan, indent=2) + "\n```\n")
            f.write("\n")

    LOG.info("Wrote reports: %s, %s, %s", json_path, csv_path, md_path)


# ---------------------------- CLI ------------------------------------------ #

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Subdomain Enumeration & Asset Discovery",
        epilog="Run only against targets you are authorized to assess.",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--top-ports", type=int, default=200, help="If nmap is missing, number of common ports to try (default: 200)")
    parser.add_argument("--shodan-key", help="Shodan API key (or set SHODAN_API_KEY)")
    parser.add_argument("--out", default="reports", help="Output directory root (default: reports)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s | %(message)s",
    )

    domain: str = args.domain.strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        LOG.error("Please pass a valid domain.")
        return 2

    shodan_key = args.shodan_key or os.getenv("SHODAN_API_KEY")
    versions = detect_versions()

    meta = RunMetadata(
        domain=domain,
        started_at=datetime.now().isoformat(timespec="seconds") + "Z",
        tool_versions=versions,
    )

    # Step 1: enumerate
    subs = sorted(enumerate_subdomains(domain))

    # Step 2/3: scan + shodan
    hosts: List[HostFinding] = []
    for host in subs:
        ips = safe_resolve(host)
        ports = nmap_scan(host)
        finding = HostFinding(hostname=host, ips=ips, ports=ports)

        # Shodan per-IP (limit to a few to keep runs quick)
        shodan_summary: Dict[str, object] = {"results": []}
        for ip in ips[:3]:
            sh = shodan_lookup(ip, shodan_key)
            if sh:
                shodan_summary["results"].append(sh)
        if shodan_summary["results"]:
            finding.shodan = shodan_summary

        hosts.append(finding)

    report = ReconReport(meta=meta, hosts=hosts)
    out_dir = Path(args.out) / domain
    write_reports(report, out_dir)

    LOG.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
        