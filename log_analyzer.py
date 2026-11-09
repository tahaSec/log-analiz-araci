#!/usr/bin/env python3
"""Analyze a local Apache/Nginx access log for noisy or suspicious patterns."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^]]+\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+[^\"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
SUSPICIOUS_PATHS = {
    "environment file": re.compile(r"(?:^|/)\.env(?:\b|/)", re.I),
    "source control metadata": re.compile(r"(?:^|/)\.git(?:/|$)", re.I),
    "common secret files": re.compile(r"(?:id_rsa|\.aws/credentials|wp-config\.php)", re.I),
    "path traversal": re.compile(r"(?:\.\./|%2e%2e%2f|%252e%252e)", re.I),
}


def configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def analyze(path: Path, failed_threshold: int, missing_threshold: int) -> dict:
    parsed = 0
    malformed = 0
    statuses: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    flags: dict[str, set[str]] = defaultdict(set)

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            match = ACCESS_LINE.match(line.rstrip("\n"))
            if not match:
                malformed += 1
                continue
            parsed += 1
            ip = match["ip"]
            status = match["status"]
            request_path = match["path"]
            statuses[status] += 1
            if status in {"401", "403"}:
                failures[ip] += 1
            if status == "404":
                missing[ip] += 1
            for label, pattern in SUSPICIOUS_PATHS.items():
                if pattern.search(request_path):
                    flags[ip].add(label)

    findings = []
    for ip, hits in sorted(failures.items(), key=lambda item: (-item[1], item[0])):
        if hits >= failed_threshold:
            findings.append({"ip": ip, "kind": "repeated_auth_failures", "count": hits,
                             "detail": f"{hits} yanıt 401/403"})
    for ip, hits in sorted(missing.items(), key=lambda item: (-item[1], item[0])):
        if hits >= missing_threshold:
            findings.append({"ip": ip, "kind": "404_burst", "count": hits,
                             "detail": f"{hits} yanıt 404"})
    for ip, kinds in sorted(flags.items()):
        findings.append({"ip": ip, "kind": "suspicious_paths", "count": len(kinds),
                         "detail": ", ".join(sorted(kinds))})

    return {"file": path.name, "parsed_lines": parsed, "malformed_lines": malformed,
            "status_counts": dict(sorted(statuses.items())), "findings": findings}


def main() -> int:
    configure_console()
    parser = argparse.ArgumentParser(description="Yerel Apache/Nginx access log dosyasını özetle.")
    parser.add_argument("logfile", type=Path, help="İncelenecek access log dosyası")
    parser.add_argument("--failed-threshold", type=int, default=8,
                        help="IP başına uyarı eşiği: 401/403 sayısı (varsayılan: 8)")
    parser.add_argument("--not-found-threshold", type=int, default=20,
                        help="IP başına uyarı eşiği: 404 sayısı (varsayılan: 20)")
    parser.add_argument("--json", action="store_true", help="Raporu JSON olarak yazdır")
    args = parser.parse_args()
    if args.failed_threshold < 1 or args.not_found_threshold < 1:
        parser.error("Eşik değerleri en az 1 olmalı.")
    if not args.logfile.is_file():
        parser.error(f"Dosya bulunamadı: {args.logfile}")

    report = analyze(args.logfile, args.failed_threshold, args.not_found_threshold)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"LOG ÖZETİ · {report['file']}")
        print(f"Okunan satır: {report['parsed_lines']}  |  Biçimi tanınmayan: {report['malformed_lines']}")
        print("HTTP durumları: " + (", ".join(f"{code}: {count}" for code, count in report["status_counts"].items()) or "yok"))
        print("\nBULGULAR")
        if not report["findings"]:
            print("Eşiklere uyan bulgu yok.")
        for finding in report["findings"]:
            print(f"- {finding['ip']:<16} {finding['kind']}: {finding['detail']}")
        print("\nBu araç ön inceleme yapar; bulgular tek başına saldırı kanıtı değildir.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        print(f"Dosya okunamadı: {error}", file=sys.stderr)
        raise SystemExit(2)

