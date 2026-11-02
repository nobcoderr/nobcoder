#!/usr/bin/env python3
"""Deterministic traced launch gate between strace readiness and bubblewrap."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from workspace_boundary_v35 import guarded_json_once


EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"


def write_once(path: Path, value: dict[str, object]) -> None:
    guarded_json_once(path, value, operation_identity="WORKER_LAUNCH_GATE_READY", generation="RUNTIME_0001")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command or not Path(command[0]).is_absolute():
        raise SystemExit("absolute command required")
    ready = Path(args.ready)
    go = Path(args.go)
    write_once(ready, {
        "record_type": "FIRST_WORKER_V35_TRACED_LAUNCH_GATE_READINESS",
        "execution_identity": EXECUTION_IDENTITY,
        "state": "TRACE_CHILD_READY_WORKER_NOT_STARTED",
        "pid": os.getpid(),
        "ready_monotonic_ns": time.monotonic_ns(),
        "ready_realtime_ns": time.time_ns(),
        "command_executable": command[0],
    })
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        if go.is_file() and not go.is_symlink():
            value = json.loads(go.read_text(encoding="utf-8"))
            if value.get("execution_identity") != EXECUTION_IDENTITY or value.get("decision") != "GO_AFTER_OBSERVER_AND_TRACE_READY":
                raise SystemExit("invalid launch gate authorization record")
            os.execv(command[0], command)
        time.sleep(0.001)
    raise SystemExit("launch gate timed out fail closed")


if __name__ == "__main__":
    raise SystemExit(main())
