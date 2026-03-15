"""
BOTSv3 CSV to project event schema converter.

This script reads the five exported BOTSv3 CSV files and writes a normalized
JSON dataset compatible with the existing detect.py rules.

Safety defaults:
- Writes only to data/botsv3_events.json by default.
- Never overwrites data/events.json unless explicitly requested.
"""

import argparse
import csv
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DEFAULT_OUTPUT = os.path.join(DATA_DIR, "botsv3_events.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")

ATTACKER_IPS = {"199.66.91.253", "13.125.33.130"}
DNS_EXFIL_DOMAIN = "brewertalk.com"

BENIGN_DOMAINS = {
    "froth.ly", "amazonaws.com", "compute.internal", "rds.amazonaws.com",
    "microsoft.com", "windows.com", "windowsupdate.com",
    "office.com", "office365.com", "live.com",
    "symantec.com", "symcd.com", "digicert.com",
    "google.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "apple.com", "akamai.net", "akamaiedge.net",
}

SYSTEM_ACCOUNTS = frozenset(
    {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "ANONYMOUS LOGON",
    }
)

BENIGN_PROCESS_NAMES = frozenset(
    {
        "lsass.exe", "svchost.exe", "winlogon.exe", "wininit.exe",
        "services.exe", "csrss.exe", "smss.exe", "explorer.exe",
        "taskhostw.exe", "sihost.exe", "ctfmon.exe", "spoolsv.exe",
        "audiodg.exe", "dwm.exe", "fontdrvhost.exe",
    }
)

PRIVESC_PATTERNS = re.compile(
    r"\brunas\b|\bpkexec\b|\bsudo\s+su\b|\bsudo\s+/bin/(ba)?sh\b"
    r"|\bsudo\s+-l\b|\bnet\s+localgroup\s+administrators\b"
    r"|\badd-localgroupmember\b|\bpsexec\b|\bat\.exe\b"
)

_event_counter: Dict[str, int] = defaultdict(int)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert BOTSv3 CSVs to project event schema")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output JSON path")
    parser.add_argument("--stats", action="store_true", help="Print stats only")
    parser.add_argument("--sample-limit", type=int, default=0, help="Limit output events for quick test runs")
    parser.add_argument(
        "--overwrite-events",
        action="store_true",
        help="Also overwrite data/events.json (disabled by default for safety)",
    )
    return parser.parse_args()


def csv_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def safe_int(value: str) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def clean_user(raw: str) -> str:
    return (raw or "").replace("\n", " ").split("$")[0].strip()


def is_internal(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second = int(parts[1])
            return 16 <= second <= 31
    return False


def is_external(ip: str) -> bool:
    ip = (ip or "").strip()
    return bool(ip) and not is_internal(ip)


def to_utc_iso(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""

    candidates = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]

    for fmt in candidates:
        try:
            parsed = datetime.strptime(raw, fmt)
            return parsed.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return raw


def make_event_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
    _event_counter[prefix] += 1
    return f"BOTS-{prefix.upper()[:3]}-{digest}-{_event_counter[prefix]:06d}"


def convert_bruteforce(path: str) -> List[Dict[str, Any]]:
    rows = csv_rows(path)
    failure_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    src_failures: Dict[str, int] = defaultdict(int)

    for row in rows:
        action = (row.get("action") or "").strip().lower()
        if action != "failure":
            continue
        src_ip = (row.get("src_ip") or "").strip()
        host = (row.get("host") or "").strip()
        user = clean_user(row.get("user") or "")
        failure_counts[(src_ip, host, user)] += 1
        if src_ip:
            src_failures[src_ip] += 1

    out: List[Dict[str, Any]] = []
    for row in rows:
        ts = to_utc_iso(row.get("_time") or "")
        if not ts:
            continue

        src_ip = (row.get("src_ip") or "").strip()
        host = (row.get("host") or "").strip()
        dest_ip = (row.get("dest_ip") or "").strip() or host
        user = clean_user(row.get("user") or "")
        action = (row.get("action") or "unknown").strip().lower()
        raw_user = row.get("user") or ""

        user_upper = user.upper()
        is_machine = "$" in raw_user or any(token in user_upper for token in SYSTEM_ACCOUNTS)
        is_attacker = src_ip in ATTACKER_IPS
        is_external_fail = action == "failure" and is_external(src_ip)
        is_burst = failure_counts[(src_ip, host, user)] >= 4 or src_failures.get(src_ip, 0) >= 4

        label = "malicious" if (is_attacker or is_external_fail or is_burst) and not is_machine else "benign"

        out.append(
            {
                "timestamp": ts,
                "event_id": make_event_id("bf", ts, src_ip, host, user, action),
                "event_type": "authentication",
                "sourcetype": "auth",
                "sourcetype_original": (row.get("sourcetype") or "").strip(),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "user": user,
                "action": action,
                "host": host,
                "label": label,
                "attack_type": "brute_force" if label == "malicious" else "none",
            }
        )
    return out


def convert_dns(path: str) -> List[Dict[str, Any]]:
    rows = csv_rows(path)
    out: List[Dict[str, Any]] = []
    for row in rows:
        ts = to_utc_iso(row.get("_time") or "")
        query = ((row.get("query") or "").strip()).lower()
        if not ts or not query:
            continue

        base_domain = ((row.get("base_domain") or "").strip()).lower()
        sub_len = safe_int(row.get("sub_length") or "") or 0
        is_benign_domain = base_domain in BENIGN_DOMAINS or any(base_domain.endswith("." + d) for d in BENIGN_DOMAINS)
        label = "malicious" if base_domain == DNS_EXFIL_DOMAIN or (sub_len > 25 and not is_benign_domain) else "benign"

        out.append(
            {
                "timestamp": ts,
                "event_id": make_event_id("dns", ts, (row.get("src_ip") or "").strip(), query),
                "event_type": "dns",
                "sourcetype": "dns",
                "sourcetype_original": (row.get("sourcetype") or "").strip(),
                "src_ip": (row.get("src_ip") or "").strip(),
                "dest_ip": (row.get("dest_ip") or "").strip(),
                "query": query,
                "query_type": (row.get("query_type") or "").strip(),
                "query_length": safe_int(row.get("query_length") or "") or len(query),
                "host": (row.get("host") or "").strip(),
                "label": label,
                "attack_type": "dns_exfiltration" if label == "malicious" else "none",
            }
        )
    return out


def convert_c2(path: str) -> List[Dict[str, Any]]:
    rows = csv_rows(path)
    conn_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        key = ((row.get("src_ip") or "").strip(), (row.get("dest_ip") or "").strip(), (row.get("dest_port") or "").strip())
        if key[0] and key[1]:
            conn_counts[key] += 1

    suspicious_ports = {"4444", "1080", "8080", "8443", "9001", "9030", "6667", "6697", "11211"}
    out: List[Dict[str, Any]] = []

    for row in rows:
        ts = to_utc_iso(row.get("_time") or "")
        src_ip = (row.get("src_ip") or "").strip()
        dest_ip = (row.get("dest_ip") or "").strip()
        dest_port_str = (row.get("dest_port") or "").strip()
        if not ts or not src_ip or not dest_ip:
            continue

        bytes_out = safe_int(row.get("bytes_out") or "")
        bytes_in = safe_int(row.get("bytes_in") or "")
        key = (src_ip, dest_ip, dest_port_str)
        connection_count = conn_counts.get(key, 0)

        low_volume = (bytes_out is None or bytes_out <= 600) and (bytes_in is None or bytes_in <= 250)
        is_beacon = is_external(dest_ip) and connection_count >= 10 and low_volume
        is_suspicious = src_ip in ATTACKER_IPS or dest_ip in ATTACKER_IPS or dest_port_str in suspicious_ports
        label = "malicious" if is_beacon or is_suspicious else "benign"

        out.append(
            {
                "timestamp": ts,
                "event_id": make_event_id("c2", ts, src_ip, dest_ip, dest_port_str),
                "event_type": "network",
                "sourcetype": "firewall",
                "sourcetype_original": (row.get("sourcetype") or "").strip(),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": safe_int(dest_port_str),
                "bytes_out": bytes_out if bytes_out is not None else 0,
                "bytes_in": bytes_in if bytes_in is not None else 0,
                "direction": "outbound" if is_internal(src_ip) and is_external(dest_ip) else "unknown",
                "action": "allowed",
                "host": (row.get("host") or "").strip(),
                "label": label,
                "attack_type": "c2_beaconing" if label == "malicious" else "none",
            }
        )
    return out


def convert_lateral(path: str) -> List[Dict[str, Any]]:
    rows = csv_rows(path)
    out: List[Dict[str, Any]] = []
    for row in rows:
        ts = to_utc_iso(row.get("_time") or "")
        src_ip = (row.get("src_ip") or "").strip()
        dest_ip = (row.get("dest_ip") or "").strip()
        if not ts or not src_ip or not dest_ip:
            continue
        external_to_internal = is_external(src_ip) and is_internal(dest_ip)
        label = "malicious" if external_to_internal else "benign"
        out.append(
            {
                "timestamp": ts,
                "event_id": make_event_id("lat", ts, src_ip, dest_ip, str(row.get("dest_port") or "")),
                "event_type": "network",
                "sourcetype": "firewall",
                "sourcetype_original": (row.get("sourcetype") or "").strip(),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": safe_int(row.get("dest_port") or ""),
                "bytes_out": safe_int(row.get("bytes_out") or "") or 0,
                "host": (row.get("host") or "").strip(),
                "label": label,
                "attack_type": "lateral_movement" if label == "malicious" else "none",
            }
        )
    return out


def convert_privesc(path: str) -> List[Dict[str, Any]]:
    rows = csv_rows(path)
    out: List[Dict[str, Any]] = []
    for row in rows:
        ts = to_utc_iso(row.get("_time") or "")
        if not ts:
            continue

        process_raw = (row.get("process") or "").strip()
        process_name = os.path.basename(process_raw).lower()
        command_line = (row.get("command_line") or "").strip()
        user = clean_user(row.get("user") or "")
        command_for_rule = command_line or process_raw
        signal = (command_for_rule + " " + process_raw).lower()
        no_signal = not process_raw and not command_line
        if no_signal:
            continue

        is_malicious = bool(PRIVESC_PATTERNS.search(signal))
        if process_name in BENIGN_PROCESS_NAMES and not is_malicious:
            label = "benign"
        else:
            label = "malicious" if is_malicious else "benign"

        out.append(
            {
                "timestamp": ts,
                "event_id": make_event_id("pe", ts, user, process_raw, command_for_rule),
                "event_type": "process",
                "sourcetype": "sysmon",
                "sourcetype_original": (row.get("sourcetype") or "").strip(),
                "src_ip": (row.get("src_ip") or "").strip(),
                "user": user,
                "process": process_name or process_raw,
                "command_line": command_line,
                "action": "escalation",
                "command": command_for_rule,
                "host": (row.get("host") or "").strip(),
                "label": label,
                "attack_type": "privilege_escalation" if label == "malicious" else "none",
            }
        )
    return out


CSV_MAP = {
    "brute_force": ("botsv3_bruteforce.csv", convert_bruteforce),
    "dns_exfiltration": ("botsv3_dns_exfil.csv", convert_dns),
    "c2_beaconing": ("botsv3_c2.csv", convert_c2),
    "lateral_movement": ("botsv3_lateral.csv", convert_lateral),
    "privilege_escalation": ("botsv3_privesc.csv", convert_privesc),
}


def print_stats(events: List[Dict[str, Any]]) -> None:
    by_attack: Dict[str, Dict[str, int]] = defaultdict(lambda: {"malicious": 0, "benign": 0})
    for event in events:
        by_attack[event.get("attack_type", "none")][event.get("label", "benign")] += 1

    print("\n----------------------------------------------------")
    print(f"BOTSv3 conversion summary ({len(events):,} events)")
    print("----------------------------------------------------")
    print(f"{'Attack type':<28} {'Malicious':>10} {'Benign':>10}")
    for attack_type, counts in sorted(by_attack.items()):
        print(f"{attack_type:<28} {counts['malicious']:>10,} {counts['benign']:>10,}")


def main() -> int:
    args = parse_args()
    all_events: List[Dict[str, Any]] = []

    for family, (filename, converter) in CSV_MAP.items():
        path = os.path.join(PROJECT_ROOT, filename)
        if not os.path.isfile(path):
            print(f"[SKIP] {filename} missing ({family})")
            continue
        converted = converter(path)
        all_events.extend(converted)
        print(f"[OK]   {filename}: {len(converted):,} events")

    if not all_events:
        print("No events converted.")
        return 1

    all_events.sort(key=lambda event: event.get("timestamp", ""))
    if args.sample_limit and args.sample_limit > 0:
        all_events = all_events[: args.sample_limit]
        print(f"[INFO] sample limit applied: {len(all_events):,} events")

    print_stats(all_events)
    if args.stats:
        return 0

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(all_events, handle, separators=(",", ":"))
    print(f"[WRITE] {args.output} ({len(all_events):,} events)")

    if args.overwrite_events:
        with open(EVENTS_FILE, "w", encoding="utf-8") as handle:
            json.dump(all_events, handle, separators=(",", ":"))
        print(f"[WRITE] {EVENTS_FILE} overwritten by explicit request")
    else:
        print("[SAFE] data/events.json was not modified")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
