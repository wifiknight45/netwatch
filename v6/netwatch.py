#!/usr/bin/env python3
"""
Netwatch v6 - ephemeral, no-logs, Signal-only alerts
- No files written to disk
- In-memory state only
- Sends alerts only via Signal REST gateway while running
- Designed to run as non-root inside Docker
"""

from __future__ import annotations
import asyncio
import os
import sys
import time
import hashlib
import json
import shlex
import subprocess
from datetime import datetime
from typing import List, Tuple, Dict, Optional

import aiohttp
import yaml

# Configuration defaults
DEFAULT_CONFIG = {
    "subnets": [],                 # empty -> auto-detect
    "scan_profile": "standard",    # quick | standard | deep
    "profiles": {
        "quick": {"ports": "1-1024", "timing": "T4"},
        "standard": {"ports": "1-10000", "timing": "T4"},
        "deep": {"ports": "1-65535", "timing": "T3"},
    },
    "enable_mdns": True,
    "quiet_hours": {"start": 23, "end": 7},
    "batching": {"enabled": True, "window_seconds": 20, "max_items": 12},
    "alert_cooldown_seconds": 3600,
    "stale_device_scans": 3,
    "signal": {"rest_url": "http://127.0.0.1:8080/v1/messages"},
    "concurrency": 8
}

# Risk tables (small)
RISKY_PORTS = {22, 23, 445, 3389, 27017, 3306, 5432, 6379}
NORMAL_PORTS = {80, 443, 53, 5353}

# In-memory state
SEEN_LAST_SCAN: Dict[str, int] = {}   # mac_or_key -> last_scan_index
KNOWN_DEVICES: Dict[str, str] = {}    # mac -> label (optional; can be empty)
ALERT_COOLDOWN: Dict[str, float] = {} # hash -> timestamp
ALERT_QUEUE: List[Tuple[str, str, str]] = []  # (level, subject, body)
SCAN_INDEX = 0

# Load config from YAML file path or environment
def load_config(path: Optional[str]) -> dict:
    cfg = DEFAULT_CONFIG.copy()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
            cfg.update(user)
            if "profiles" not in cfg:
                cfg["profiles"] = DEFAULT_CONFIG["profiles"]
    return cfg

def now_ts() -> str:
    return datetime.utcnow().isoformat(sep=" ", timespec="seconds")

def md5_hash(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def in_quiet_hours(cfg: dict) -> bool:
    start = int(cfg["quiet_hours"]["start"])
    end = int(cfg["quiet_hours"]["end"])
    h = datetime.now().hour
    if start <= end:
        return start <= h < end
    else:
        return h >= start or h < end

# Unprivileged subnet detection (best-effort)
def detect_subnet() -> str:
    try:
        route = subprocess.check_output(shlex.split("ip -4 route show default"), text=True)
        iface = route.split()[4]
        addr = subprocess.check_output(shlex.split(f"ip -o -f inet addr show {iface}"), text=True)
        cidr = addr.split()[3]
        return cidr
    except Exception:
        return "192.168.1.0/24"

# Run nmap ping sweep in unprivileged mode
async def nmap_ping(subnet: str) -> List[str]:
    cmd = ["nmap", "-sn", "--unprivileged", subnet, "-oG", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        lines = out.decode().splitlines()
        hosts = []
        for line in lines:
            if line.startswith("Host:"):
                parts = line.split()
                if len(parts) >= 2:
                    hosts.append(parts[1])
        return hosts
    except FileNotFoundError:
        return []

# Unprivileged port scan using nmap -sT
async def nmap_scan_ports(ip: str, ports: str, timing: str) -> List[Tuple[int, str]]:
    cmd = ["nmap", "-p", ports, f"-{timing}", "-sT", "--open", "-oG", "-", ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        lines = out.decode().splitlines()
        results = []
        for line in lines:
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip()
                for seg in parts.split(","):
                    seg = seg.strip()
                    if not seg:
                        continue
                    fields = seg.split("/")
                    try:
                        pnum = int(fields[0])
                        state = fields[1]
                        results.append((pnum, state))
                    except Exception:
                        continue
        return results
    except FileNotFoundError:
        return []

# Alert manager: batching, cooldown, send via Signal REST
class AlertManager:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.queue = []
        self.cooldown = cfg["alert_cooldown_seconds"]
        self.batch_window = cfg["batching"]["window_seconds"]
        self.max_items = cfg["batching"]["max_items"]
        self.signal_url = cfg["signal"]["rest_url"]
        self.signal_number = os.environ.get("SIGNAL_NUMBER", "")
        self.signal_recipients = os.environ.get("SIGNAL_RECIPIENTS", "")
        self.session = aiohttp.ClientSession()

    def _cooldown_ok(self, key: str) -> bool:
        h = md5_hash(key)
        last = ALERT_COOLDOWN.get(h)
        if last is None:
            return True
        return (time.time() - last) >= self.cooldown

    def _record(self, key: str):
        h = md5_hash(key)
        ALERT_COOLDOWN[h] = time.time()

    def queue_alert(self, subject: str, body: str, level: str = "info"):
        key = f"{subject}:{body}"
        if not self._cooldown_ok(key):
            return
        self.queue.append((level, subject, body))
        self._record(key)

    async def flush(self):
        if not self.queue:
            return
        # batch
        batches = []
        cur = []
        for item in self.queue:
            cur.append(item)
            if len(cur) >= self.max_items:
                batches.append(cur)
                cur = []
        if cur:
            batches.append(cur)
        for batch in batches:
            subj = "Netwatch Alerts"
            body_lines = []
            for lvl, s, b in batch:
                body_lines.append(f"{s}: {b}")
            body = "\n".join(body_lines[:200])
            # send via Signal REST only if configured
            if self.signal_number and self.signal_recipients:
                await self._send_signal(subj, body)
            # do not write logs or files
        self.queue = []

    async def _send_signal(self, subject: str, body: str):
        payload = {
            "message": f"{subject}\n{body}",
            "number": self.signal_number,
            "recipients": [r.strip() for r in self.signal_recipients.split(",") if r.strip()]
        }
        try:
            async with self.session.post(self.signal_url, json=payload, timeout=10) as resp:
                # do not write any logs; only keep ephemeral status in memory
                _ = resp.status
        except Exception:
            # swallow errors silently to avoid writing logs
            pass

    async def close(self):
        await self.session.close()

# Main scan loop (single run)
async def run_scan_once(cfg: dict, alert_mgr: AlertManager):
    global SCAN_INDEX
    SCAN_INDEX += 1
    scan_id = SCAN_INDEX
    subnets = cfg.get("subnets") or []
    if not subnets:
        subnets = [detect_subnet()]
    profile = cfg["profiles"].get(cfg["scan_profile"], cfg["profiles"]["standard"])
    ports = profile["ports"]
    timing = profile["timing"]

    # discovery
    discovered = {}  # key -> ip
    for subnet in subnets:
        hosts = await nmap_ping(subnet)
        for ip in hosts:
            key = f"NMAP:{ip}"
            discovered[key] = ip

    # concurrent port scans
    sem = asyncio.Semaphore(cfg.get("concurrency", 8))
    async def scan_host(key: str, ip: str):
        async with sem:
            open_ports = await nmap_scan_ports(ip, ports, timing)
            return key, ip, open_ports

    tasks = [scan_host(k, v) for k, v in discovered.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    new_devices = []
    risky_findings = []
    for res in results:
        if isinstance(res, Exception):
            continue
        key, ip, open_ports = res
        mac = key if not key.startswith("NMAP:") else key
        # update seen tracker in memory
        SEEN_LAST_SCAN[mac] = scan_id
        # determine label if known
        label = KNOWN_DEVICES.get(mac.upper(), "UNKNOWN")
        # evaluate risk
        host_risk = 0
        for pnum, state in open_ports:
            if pnum in RISKY_PORTS:
                host_risk += 10
                risky_findings.append(f"{ip}:{pnum}")
            elif pnum in NORMAL_PORTS:
                host_risk += 0
            else:
                host_risk += 1
        if label == "UNKNOWN":
            new_devices.append(f"{ip} [{mac}]")
    # stale detection (in-memory)
    # find known devices not seen for N scans
    stale_threshold = cfg["stale_device_scans"]
    for mac, last in list(SEEN_LAST_SCAN.items()):
        if (scan_id - last) >= stale_threshold:
            label = KNOWN_DEVICES.get(mac.upper(), "UNKNOWN")
            alert_mgr.queue_alert("Stale Device", f"{mac} ({label}) not seen for {scan_id - last} scans", "critical")

    # queue alerts
    for d in new_devices:
        # respect quiet hours for non-critical? new devices are critical
        alert_mgr.queue_alert("Unknown Device", d, "critical")
    for r in risky_findings:
        alert_mgr.queue_alert("Risky Port", r, "critical")

    # flush alerts (batched)
    await alert_mgr.flush()

# Entrypoint
async def main():
    cfg_path = os.environ.get("NETWATCH_CONFIG_PATH", "")
    cfg = load_config(cfg_path if cfg_path else None)
    alert_mgr = AlertManager(cfg)

    # quick signal-test mode
    if len(sys.argv) > 1 and sys.argv[1] == "signal-test":
        if not os.environ.get("SIGNAL_NUMBER") or not os.environ.get("SIGNAL_RECIPIENTS"):
            # cannot print logs; write minimal stdout for operator
            print("MISSING_SIGNAL_ENV")
            await alert_mgr.close()
            return
        await alert_mgr._send_signal("Netwatch v6 test", "This is a test message from Netwatch v6")
        await alert_mgr.close()
        print("SENT_TEST")
        return

    # run once and exit (ephemeral). For continuous mode, run in a loop externally.
    await run_scan_once(cfg, alert_mgr)
    await alert_mgr.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
