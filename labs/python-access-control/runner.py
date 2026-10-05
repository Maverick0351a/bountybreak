"""Synthetic access-control fixture; contains no target code or data."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import sys


RECORDS = {
    "alice": {"owner": "alice", "marker": "CONTROLLED-ALICE"},
    "bob": {"owner": "bob", "marker": "CONTROLLED-BOB"},
}


def vulnerable_read(actor: str, record_id: str) -> dict:
    # Intentionally missing the object-owner check for this synthetic fixture.
    return RECORDS[record_id]


def guarded_read(actor: str, record_id: str) -> dict:
    record = RECORDS[record_id]
    if record["owner"] != actor:
        raise PermissionError("record owner mismatch")
    return record


def verify_isolation() -> bool:
    status = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        network_blocked = probe.connect_ex(("1.1.1.1", 53)) != 0
    finally:
        probe.close()
    checks = {
        "uid": os.getuid() == 65534,
        "caps": status.get("CapEff") == "0000000000000000",
        "no_new_privs": status.get("NoNewPrivs") == "1",
        "host_mount": not Path("/mnt/c").exists(),
        "network": network_blocked,
    }
    print(
        "ISOLATION "
        f"uid={'dropped' if checks['uid'] else 'unexpected'} "
        f"caps={'none' if checks['caps'] else 'unexpected'} "
        f"no_new_privs={'yes' if checks['no_new_privs'] else 'no'} "
        f"host_mount={'absent' if checks['host_mount'] else 'visible'} "
        f"network={'blocked' if checks['network'] else 'reachable'}"
    )
    return all(checks.values())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: runner.py candidate|negative-control", file=sys.stderr)
        return 2
    if not verify_isolation():
        print("isolation self-check failed", file=sys.stderr)
        return 3
    if sys.argv[1] == "candidate":
        record = vulnerable_read("alice", "bob")
        print(f"OBSERVED_UNAUTHORIZED_READ marker={record['marker']}")
        return 0
    if sys.argv[1] == "negative-control":
        try:
            guarded_read("alice", "bob")
        except PermissionError:
            print("DENIED_BY_OWNER_CHECK")
            return 0
        print("UNEXPECTED_CONTROL_BYPASS")
        return 1
    print("unknown case", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
