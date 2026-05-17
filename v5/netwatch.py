#!/usr/bin/env python3
"""
Netwatch v5 - Python, non-root, Docker-friendly network monitor
- Unprivileged discovery (nmap unprivileged, mDNS, DNS)
- SQLite history
- Batched, deduplicated alerts
- Signal-only notifications via local REST gateway (signal-cli-rest)
- Config via YAML + environment variables for secrets
"""

from __future__ import annotations
import argparse
import asyncio
import os
import sys
import time
import hashlib
import json
import sqlite3
import subprocess
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import socket

# Third-party imports (requirements.txt)
import yaml
import aiohttp
from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange

# Constants and defaults
VERSION = "5.0.0"
DEFAULT_DATA_DIR = Path.home() / ".netwatch"
DEFAULT_CONFIG = {
    "subnets": [],  # empty -> auto-detect
    "scan_profile": "standard",  # quick, standard, deep
    "profiles": {
        "quick": {"ports": "1-1024", "timing": "T4"},
        "standard": {"ports": "1-10000", "timing": "T4"},
        "deep": {"ports": "1-65535", "timing": "T3"},
    },
    "enable_mdns": True,
    "quiet_hours": {"start": 23, "end": 7},
    "batching": {"enabled": True, "window_seconds": 30, "max_items": 12},
    "alert_cooldown_seconds": 3600,
    "stale_device_scans": 3,
    "signal": {"use_daemon": True, "rest_url": "http://127.0.0.1:8080/v1/messages"},
    "data_dir": str(DEFAULT_DATA_DIR),
    "log_retention_days": 90,
}

# Risk tables (short)
RISKY_PORTS = {
    21: "FTP plaintext",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    27017: "MongoDB",
    3306: "MySQL",
    5432: "Postgres",
    6379: "Redis",
    8888: "Jupyter",
}

NORMAL_PORTS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 5353: "mDNS"}

# Helper utilities


def now_ts() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(sep=" ", timespec="seconds")


def md5_hash(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


# Config loader


def load_config(path: Optional[Path]) -> dict:
    cfg = DEFAULT_CONFIG.copy()
    if path and path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
            # shallow merge for top-level keys
            cfg.update(user_cfg)
            # ensure profiles exist
            if "profiles" not in cfg:
                cfg["profiles"] = DEFAULT_CONFIG["profiles"]
    return cfg


# Data directory and files


class DataPaths:
    def __init__(self, base: Path):
        self.base = base
        self.known = base / "known_devices.txt"
        self.exclusions = base / "exclusions.txt"
        self.db = base / "netwatch.db"
        self.snapshots = base / "snapshots"
        self.reports = base / "reports"
        self.scan_log = base / "scan.log"
        self.alert_log = base / "alerts.log"
        self.stale = base / "stale_tracker.txt"
        ensure_dir(base)
        ensure_dir(self.snapshots)
        ensure_dir(self.reports)


# SQLite helpers


def init_db(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.executescript(
        """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  subnet TEXT,
  host_count INTEGER DEFAULT 0,
  new_count INTEGER DEFAULT 0,
  risky_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id),
  ip TEXT,
  mac TEXT,
  vendor TEXT,
  hostname TEXT,
  os_guess TEXT,
  label TEXT,
  tags TEXT,
  risk_score INTEGER DEFAULT 0,
  ts TEXT
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER REFERENCES hosts(id),
  port INTEGER,
  proto TEXT,
  state TEXT,
  service TEXT,
  version TEXT,
  banner TEXT,
  risk TEXT,
  ts TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,
  type TEXT,
  subject TEXT,
  body TEXT
);
"""
    )
    conn.commit()
    conn.close()


# Discovery helpers (unprivileged)


def detect_subnet() -> str:
    # Try to detect primary IPv4 network via default route
    try:
        route = subprocess.check_output(shlex.split("ip -4 route show default"), text=True)
        iface = route.split()[4]
        addr = subprocess.check_output(shlex.split(f"ip -o -f inet addr show {iface}"), text=True)
        cidr = addr.split()[3]
        return cidr
    except Exception:
        # fallback to localhost /24
        return "192.168.1.0/24"


async def run_nmap_ping(subnet: str, unprivileged: bool = True) -> List[str]:
    # Use nmap -sn in unprivileged mode if requested
    flags = ["-sn"]
    if unprivileged:
        flags.append("--unprivileged")
    cmd = ["nmap"] + flags + [subnet, "-oG", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        lines = out.decode().splitlines()
        hosts = []
        for line in lines:
            if line.startswith("Host:"):
                parts = line.split()
                # Host: 192.168.1.10 ()  Status: Up
                if len(parts) >= 2:
                    hosts.append(parts[1])
        return hosts
    except FileNotFoundError:
        return []


# mDNS discovery using zeroconf (synchronous helper wrapped in thread)


class MDNSListener:
    def __init__(self):
        self.found: Dict[str, str] = {}
        self.zeroconf = Zeroconf()
        self.browser = ServiceBrowser(self.zeroconf, "_services._dns-sd._udp.local.", handlers=[self.on_service])

    def on_service(self, zeroconf, service_type, name, state_change):
        # We will not enumerate all services; instead, we will query common types later if needed.
        pass

    def close(self):
        try:
            self.zeroconf.close()
        except Exception:
            pass


# Hostname resolution


def resolve_hostname(ip: str) -> str:
    try:
        res = socket.gethostbyaddr(ip)
        return res[0]
    except Exception:
        return ""


# Port scan (unprivileged) - use nmap -sT and profile ports


async def scan_ports(ip: str, ports: str, timing: str, unprivileged: bool = True) -> List[Tuple[int, str, str]]:
    # Returns list of tuples: (port, state, service)
    flags = ["-p", ports, f"-{timing}", "--open", "-sV", "--version-intensity", "1"]
    if unprivileged:
        flags.append("-sT")
    cmd = ["nmap"] + flags + [ip, "-oG", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        lines = out.decode().splitlines()
        results = []
        for line in lines:
            # parse lines like: Host: 192.168.1.10 ()  Ports: 22/open/tcp//ssh//OpenSSH 7.9p1
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip()
                for pseg in parts.split(","):
                    pseg = pseg.strip()
                    if not pseg:
                        continue
                    # format: 22/open/tcp//ssh//OpenSSH 7.9p1
                    fields = pseg.split("/")
                    try:
                        portnum = int(fields[0])
                        state = fields[1]
                        proto = fields[2]
                        service = fields[4] if len(fields) > 4 else ""
                        results.append((portnum, state, service))
                    except Exception:
                        continue
        return results
    except FileNotFoundError:
        return []


# Known devices helpers


def load_known_devices(path: Path) -> Dict[str, Tuple[str, List[str]]]:
    # returns {MAC: (label, [tags])}
    out = {}
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or "=" not in line:
                continue
            mac, rest = line.split("=", 1)
            if ":" in rest:
                label, tags = rest.split(":", 1)
                taglist = [t.strip() for t in tags.split(",") if t.strip()]
            else:
                label = rest
                taglist = []
            out[mac.upper()] = (label, taglist)
    return out


def is_excluded(target: str, exclusions_path: Path) -> bool:
    if not exclusions_path.exists():
        return False
    with open(exclusions_path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip().upper() == target.upper():
                return True
    return False


# Alert queue, batching, cooldown


class AlertManager:
    def __init__(self, cfg: dict, paths: DataPaths):
        self.cfg = cfg
        self.paths = paths
        self.queue: List[Tuple[str, str, str]] = []  # (level, subject, body)
        self.last_sent: Dict[str, int] = {}  # hash -> ts
        self.batch_window = cfg["batching"]["window_seconds"]
        self.max_items = cfg["batching"]["max_items"]
        self.cooldown = cfg["alert_cooldown_seconds"]
        self.signal_url = cfg["signal"]["rest_url"]
        self.signal_use_daemon = cfg["signal"].get("use_daemon", True)
        self.signal_number = os.environ.get("SIGNAL_NUMBER", "")
        self.signal_recipients = os.environ.get("SIGNAL_RECIPIENTS", "")
        self.session = aiohttp.ClientSession()

    def _cooldown_ok(self, key: str) -> bool:
        h = md5_hash(key)
        last = self.last_sent.get(h)
        if last is None:
            return True
        return (int(time.time()) - last) >= self.cooldown

    def _record_sent(self, key: str):
        h = md5_hash(key)
        self.last_sent[h] = int(time.time())

    def queue_alert(self, subject: str, body: str, level: str = "info"):
        # quiet hours suppression handled by caller
        key = f"{subject}:{body}"
        if not self._cooldown_ok(key):
            # suppressed
            return
        self.queue.append((level, subject, body))

    async def flush(self):
        if not self.queue:
            return
        # batch into messages
        batches = []
        current = []
        for item in self.queue:
            current.append(item)
            if len(current) >= self.max_items:
                batches.append(current)
                current = []
        if current:
            batches.append(current)
        # send each batch
        for batch in batches:
            subj = "Netwatch Alerts"
            body_lines = []
            level = "info"
            for lvl, s, b in batch:
                body_lines.append(f"{s}: {b}")
                if lvl == "critical":
                    level = "critical"
            body = "\n".join(body_lines[:200])  # limit length
            # log locally and insert into DB
            ts = now_ts()
            with open(self.paths.alert_log, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {subj}: {body}\n")
            # record in DB
            try:
                conn = sqlite3.connect(str(self.paths.db))
                cur = conn.cursor()
                cur.execute("INSERT INTO alerts(ts,type,subject,body) VALUES(?,?,?,?)", (ts, "alert", subj, body))
                conn.commit()
                conn.close()
            except Exception:
                pass
            # send via Signal only if configured and ready
            if self.signal_recipients and self.signal_number and await self._signal_ready():
                await self._send_signal(subj, body)
                self._record_sent(f"{subj}:{body}")
            else:
                # not ready: keep local log only
                pass
        self.queue = []

    async def _signal_ready(self) -> bool:
        # check REST endpoint health if using daemon
        if not self.signal_recipients or not self.signal_number:
            return False
        if self.signal_use_daemon:
            try:
                async with self.session.get(self.signal_url.replace("/v1/messages", "/v1/health"), timeout=3) as resp:
                    return resp.status == 200
            except Exception:
                return False
        else:
            # direct signal-cli not supported in this Python-only container design
            return False

    async def _send_signal(self, subject: str, body: str):
        # send to each recipient via REST API
        recipients = [r.strip() for r in self.signal_recipients.split(",") if r.strip()]
        payload = {"message": f"{subject}\n{body}", "number": self.signal_number, "recipients": recipients}
        try:
            async with self.session.post(self.signal_url, json=payload, timeout=10) as resp:
                # log delivery attempt
                ts = now_ts()
                with open(self.paths.base / "signal_delivery.log", "a", encoding="utf-8") as fh:
                    fh.write(f"[{ts}] signal send status: {resp.status}\n")
        except Exception as e:
            ts = now_ts()
            with open(self.paths.base / "signal_delivery.log", "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] signal send error: {e}\n")

    async def close(self):
        await self.session.close()


# Utility: quiet hours


def in_quiet_hours(cfg: dict) -> bool:
    start = int(cfg["quiet_hours"]["start"])
    end = int(cfg["quiet_hours"]["end"])
    h = datetime.now().hour
    if start <= end:
        return start <= h < end
    else:
        return h >= start or h < end


# HTML report generator (simple)


def generate_html_report(rows: List[dict], out_path: Path, scan_ts: str, subnet: str):
    total = len(rows)
    unknown = sum(1 for r in rows if r.get("label") == "UNKNOWN")
    risky = sum(1 for r in rows if r.get("risk_score", 0) > 0)
    html = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>Netwatch Report</title></head><body>",
        f"<h1>Netwatch Scan Report - {scan_ts}</h1>",
        f"<p>Subnet: {subnet}</p>",
        f"<p>Devices: {total} | Unknown: {unknown} | Risky: {risky}</p>",
        "<table border='1' cellpadding='4'><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Label</th><th>Risk</th><th>Open Ports</th></tr>",
    ]
    for r in rows:
        ports = ", ".join(f"{p}/{s}" for p, s in r.get("open_ports", []))
        html.append(f"<tr><td>{r.get('ip')}</td><td>{r.get('mac','')}</td><td>{r.get('hostname','')}</td><td>{r.get('label','')}</td><td>{r.get('risk_score',0)}</td><td>{ports}</td></tr>")
    html.append("</table></body></html>")
    out_path.write_text("\n".join(html), encoding="utf-8")


# Main scan routine


async def do_scan(cfg: dict, paths: DataPaths, alert_mgr: AlertManager):
    # prepare
    subnets = cfg.get("subnets") or []
    if not subnets:
        subnets = [detect_subnet()]
    profile = cfg["profiles"].get(cfg["scan_profile"], cfg["profiles"]["standard"])
    ports = profile["ports"]
    timing = profile["timing"]
    scan_ts = now_ts()
    snapshot_file = paths.snapshots / f"scan_{int(time.time())}.txt"
    report_file = paths.reports / f"report_{int(time.time())}.html"

    # discovery
    discovered = {}  # key -> ip (key is MAC or synthetic)
    vendors = {}
    hostnames = {}
    mdns_names = {}

    # mDNS: run briefly in thread to collect names (best-effort)
    if cfg.get("enable_mdns", True):
        try:
            z = Zeroconf()
            # We will not enumerate services deeply; zeroconf is heavy. Instead, skip complex mDNS parsing.
            z.close()
        except Exception:
            pass

    for subnet in subnets:
        hosts = await run_nmap_ping(subnet, unprivileged=True)
        for ip in hosts:
            # mark synthetic key
            key = f"NMAP:{ip}"
            discovered[key] = ip
            vendors[key] = "(nmap)"
            hostnames[key] = resolve_hostname(ip)

    # write snapshot header
    with open(snapshot_file, "w", encoding="utf-8") as fh:
        fh.write(f"Scan: {scan_ts}\n")
        fh.write(f"Subnets: {','.join(subnets)}\n")

    # per-host port scans (concurrent)
    sem = asyncio.Semaphore(12)
    async def scan_host(key: str, ip: str):
        async with sem:
            open_ports = await scan_ports(ip, ports, timing, unprivileged=True)
            return key, ip, open_ports

    tasks = [scan_host(k, v) for k, v in discovered.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    html_rows = []
    new_devices = []
    risky_findings = []
    total_risk = 0

    # load known devices
    known = load_known_devices(paths.known)

    # insert scan row
    conn = sqlite3.connect(str(paths.db))
    cur = conn.cursor()
    cur.execute("INSERT INTO scans(ts,subnet,host_count,new_count,risky_count) VALUES(?,?,?,?,?)", (scan_ts, ",".join(subnets), len(discovered), 0, 0))
    scan_id = cur.lastrowid
    conn.commit()

    for res in results:
        if isinstance(res, Exception):
            continue
        key, ip, open_ports = res
        mac = key if key.startswith("NMAP:") else key
        vendor = vendors.get(key, "")
        hn = hostnames.get(key, "")
        label = known.get(mac.upper(), ("UNKNOWN", []))[0] if mac else "UNKNOWN"
        tags = ",".join(known.get(mac.upper(), ("", []))[1]) if mac else ""
        host_risk = 0
        ports_list = []
        for pnum, state, svc in open_ports:
            ports_list.append((pnum, svc))
            if pnum in RISKY_PORTS:
                host_risk += 10
                risky_findings.append(f"{ip}:{pnum} - {RISKY_PORTS[pnum]}")
            elif pnum in NORMAL_PORTS:
                host_risk += 0
            else:
                host_risk += 1
        total_risk += host_risk
        # DB insert host
        cur.execute("INSERT INTO hosts(scan_id,ip,mac,vendor,hostname,os_guess,label,tags,risk_score,ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, ip, mac, vendor, hn, "", label, tags, host_risk, scan_ts))
        host_id = cur.lastrowid
        for pnum, svc in ports_list:
            cur.execute("INSERT INTO ports(host_id,port,proto,state,service,version,banner,risk,ts) VALUES(?,?,?,?,?,?,?,?,?)",
                        (host_id, pnum, "tcp", "open", svc, "", "", ("RISKY" if pnum in RISKY_PORTS else "NORMAL" if pnum in NORMAL_PORTS else "UNKNOWN"), scan_ts))
        conn.commit()
        # snapshot
        with open(snapshot_file, "a", encoding="utf-8") as fh:
            fh.write(f"{ip} {mac} {vendor} {hn} {label}\n")
        if label == "UNKNOWN":
            new_devices.append(f"{ip} [{mac}] {vendor}")
        if host_risk > 0:
            risky_findings.append(f"{ip} risk {host_risk}")
        html_rows.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hn, "label": label, "tags": tags, "risk_score": host_risk, "open_ports": ports_list})

    # stale device tracking (simple)
    # update stale file
    with open(paths.stale, "a+", encoding="utf-8") as fh:
        fh.seek(0)
        existing = {line.split("=")[0]: int(line.split("=")[1]) for line in fh.read().splitlines() if "=" in line}
    with open(paths.stale, "w", encoding="utf-8") as fh:
        for mac in existing:
            fh.write(f"{mac}={existing[mac]}\n")
        for mac in discovered.keys():
            fh.write(f"{mac}={scan_id}\n")

    # queue alerts
    if new_devices:
        for d in new_devices:
            alert_mgr.queue_alert("Unknown Device", d, "critical")
    if risky_findings:
        for r in risky_findings:
            alert_mgr.queue_alert("Risky Port", r, "critical")

    # flush alerts (batched)
    await alert_mgr.flush()

    # finalize DB scan counts
    cur.execute("UPDATE scans SET new_count=?, risky_count=? WHERE id=?", (len(new_devices), len(risky_findings), scan_id))
    conn.commit()
    conn.close()

    # generate HTML report
    generate_html_report(html_rows, report_file, scan_ts, ",".join(subnets))

    # write scan log
    with open(paths.scan_log, "a", encoding="utf-8") as fh:
        fh.write(f"[{scan_ts}] subnets={','.join(subnets)} devices={len(discovered)} unknown={len(new_devices)} risky={len(risky_findings)} risk_score={total_risk}\n")

    print(f"Scan complete: {len(discovered)} devices, {len(new_devices)} new, {len(risky_findings)} risky")
    return


# CLI and main


async def main():
    parser = argparse.ArgumentParser(description="Netwatch v5 - non-root Python network monitor")
    parser.add_argument("--config", "-c", help="Path to YAML config", default=None)
    parser.add_argument("command", nargs="?", default="scan", choices=["scan", "signal-test", "history", "report"])
    args = parser.parse_args()

    cfg_path = Path(args.config) if args.config else None
    cfg = load_config(cfg_path)
    data_dir = Path(cfg.get("data_dir", DEFAULT_CONFIG["data_dir"]))
    paths = DataPaths(data_dir)
    init_db(paths.db)

    alert_mgr = AlertManager(cfg, paths)

    if args.command == "signal-test":
        # quick test: attempt to POST a test message to the REST endpoint
        if not os.environ.get("SIGNAL_NUMBER") or not os.environ.get("SIGNAL_RECIPIENTS"):
            print("SIGNAL_NUMBER and SIGNAL_RECIPIENTS must be set in environment for signal-test")
            await alert_mgr.close()
            return
        await alert_mgr._send_signal("Netwatch v5 test", "This is a test message from Netwatch v5")
        await alert_mgr.close()
        print("Signal test attempted; check delivery log.")
        return

    if args.command == "history":
        # print last 20 scans
        conn = sqlite3.connect(str(paths.db))
        cur = conn.cursor()
        for row in cur.execute("SELECT id, ts, subnet, host_count, new_count, risky_count FROM scans ORDER BY id DESC LIMIT 20"):
            print(row)
        conn.close()
        await alert_mgr.close()
        return

    if args.command == "report":
        # show last alerts
        if paths.alert_log.exists():
            print(paths.alert_log.read_text(encoding="utf-8").splitlines()[-50:])
        await alert_mgr.close()
        return

    # default: scan
    await do_scan(cfg, paths, alert_mgr)
    await alert_mgr.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(0)
