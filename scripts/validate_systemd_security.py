#!/usr/bin/env python3
"""Validate systemd service files against security hardening contracts."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

MAX_EXPOSURE_SCORE = 4.8

MANDATORY_SYSTEMD_DIRECTIVES = [
    "UserOrDynamicUser",
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectClock",
    "ProtectControlGroups",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RestrictSUIDSGID",
    "UMask",
    "RestrictAddressFamilies_AF_PACKET",
    "RestrictAddressFamilies_AF_NETLINK",
    "RestrictNamespaces_user",
    "RestrictNamespaces_pid",
    "RestrictNamespaces_net",
    "RestrictNamespaces_uts",
    "RestrictNamespaces_mnt",
    "RestrictNamespaces_cgroup",
    "RestrictNamespaces_ipc",
]

REQUIRED_UNIT_TEXT_DIRECTIVES = [
    (r"StateDirectory\s*=\s*camellia-remote", "StateDirectory=camellia-remote"),
    (r"StateDirectoryMode\s*=\s*0700", "StateDirectoryMode=0700"),
    (r"TimeoutStopSec\s*=\s*30s", "TimeoutStopSec=30s"),
    (r"User\s*=\s*camellia-remote", "User=camellia-remote"),
    (r"Group\s*=\s*camellia-remote", "Group=camellia-remote"),
    (r"UMask\s*=\s*0077", "UMask=0077"),
    (r"ProtectSystem\s*=\s*strict", "ProtectSystem=strict"),
]


def validate_unit(unit_path: Path) -> list[str]:
    errors: list[str] = []
    text = unit_path.read_text(encoding="utf-8")

    # 1. Text-based directive checks
    for pattern, name in REQUIRED_UNIT_TEXT_DIRECTIVES:
        if not re.search(pattern, text):
            errors.append(f"{unit_path.name}: missing required directive '{name}'")

    # 2. Check if systemd-analyze is available
    if not shutil.which("systemd-analyze"):
        print(f"WARNING: systemd-analyze not found, skipped offline analysis for {unit_path.name}")
        return errors

    # 3. systemd-analyze security offline analysis
    try:
        proc = subprocess.run(
            ["systemd-analyze", "security", "--offline=yes", "--json=short", str(unit_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
    except Exception as exc:
        errors.append(f"{unit_path.name}: systemd-analyze security failed: {exc}")
        return errors

    # 4. Check mandatory security directives
    set_fields = {item["json_field"] for item in data if item.get("set")}
    for directive in MANDATORY_SYSTEMD_DIRECTIVES:
        if directive not in set_fields:
            errors.append(f"{unit_path.name}: security directive '{directive}' is NOT satisfied")

    # 5. Extract overall score via systemd-analyze security output
    try:
        summary_proc = subprocess.run(
            ["systemd-analyze", "security", "--offline=yes", str(unit_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        match = re.search(r"Overall exposure level.*:\s*([0-9.]+)", summary_proc.stdout)
        if match:
            score = float(match.group(1))
            if score > MAX_EXPOSURE_SCORE:
                errors.append(
                    f"{unit_path.name}: overall exposure score {score:.1f} exceeds threshold {MAX_EXPOSURE_SCORE:.1f}"
                )
        else:
            errors.append(f"{unit_path.name}: failed to parse overall exposure score from output")
    except Exception as exc:
        errors.append(f"{unit_path.name}: failed to obtain score summary: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("units", nargs="+", type=Path, help="Systemd unit files to validate")
    args = parser.parse_args()

    all_errors: list[str] = []
    for unit in args.units:
        if not unit.is_file():
            all_errors.append(f"File not found: {unit}")
            continue
        errors = validate_unit(unit)
        if errors:
            all_errors.extend(errors)
        else:
            print(f"[systemd-security] OK: {unit.name} conforms to security baseline (score <= {MAX_EXPOSURE_SCORE})")

    if all_errors:
        print("\n[systemd-security] VALIDATION FAILED:", file=sys.stderr)
        for err in all_errors:
            print(f"  ✗ {err}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
