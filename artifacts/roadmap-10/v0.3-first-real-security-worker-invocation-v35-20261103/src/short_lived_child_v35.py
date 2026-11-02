#!/usr/bin/env python3
"""Deterministic inert process-topology fixtures for V19 temporal coverage."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def append_ledger(path: Path | None, event: str, **evidence: object) -> None:
    if path is None:
        return
    row = {
        "event": event,
        "host_pid": os.getpid(),
        "parent_host_pid": os.getppid(),
        "monotonic_ns": time.monotonic_ns(),
        **evidence,
    }
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def immediate(ledger: Path | None, count: int = 6) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="immediate", count=count)
    children: list[int] = []
    for _ in range(count):
        pid = os.fork()
        if pid == 0:
            append_ledger(ledger, "CHILD_ALIVE", fixture_class="immediate")
            os._exit(0)
        children.append(pid)
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="immediate", child_host_pid=pid)
    return all(os.waitpid(pid, 0)[1] == 0 for pid in children)


def sequential(ledger: Path | None, count: int = 6) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="sequential", count=count)
    ok = True
    for _ in range(count):
        process = subprocess.Popen(["/bin/true"])
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="sequential", child_host_pid=process.pid)
        ok = process.wait() == 0 and ok
    return ok


def overlapping(ledger: Path | None, count: int = 6) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="overlapping", count=count)
    processes = [subprocess.Popen(["/bin/sleep", "0.03"]) for _ in range(count)]
    for process in processes:
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="overlapping", child_host_pid=process.pid)
    return all(process.wait() == 0 for process in processes)


def long_lived(ledger: Path | None, count: int = 4) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="long_lived", count=count)
    processes = [subprocess.Popen(["/bin/sleep", "0.08"]) for _ in range(count)]
    for process in processes:
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="long_lived", child_host_pid=process.pid)
    return all(process.wait() == 0 for process in processes)


def nested(ledger: Path | None) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="nested", count=2)
    code = (
        "import subprocess,sys; "
        "p=subprocess.Popen(['/bin/true']); "
        "print(p.pid, flush=True); "
        "sys.exit(p.wait())"
    )
    process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="nested", child_host_pid=process.pid)
    grandchild = process.stdout.readline().strip() if process.stdout is not None else ""
    if grandchild.isdigit():
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="nested-grandchild", child_host_pid=int(grandchild))
    return process.wait() == 0 and grandchild.isdigit()


def thread_descendants(ledger: Path | None, count: int = 4) -> bool:
    append_ledger(ledger, "SPAWN_REQUESTED", fixture_class="thread", count=count)
    threads = [threading.Thread(target=lambda: time.sleep(0.01)) for _ in range(count)]
    for thread in threads:
        thread.start()
        append_ledger(ledger, "SPAWN_SUCCEEDED", fixture_class="thread", child_native_id=thread.native_id)
    for thread in threads:
        thread.join()
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("long-lived", "sequential", "overlapping", "immediate", "nested", "combined"),
        default="combined",
    )
    parser.add_argument("--fixture-ledger")
    args = parser.parse_args()
    ledger = Path(args.fixture_ledger) if args.fixture_ledger else None
    operations = {
        "long-lived": (long_lived,),
        "sequential": (sequential,),
        "overlapping": (overlapping,),
        "immediate": (immediate,),
        "nested": (nested,),
        "combined": (long_lived, sequential, overlapping, immediate, nested, thread_descendants),
    }[args.mode]
    append_ledger(ledger, "FIXTURE_STARTED", fixture_class=args.mode)
    ok = all(operation(ledger) for operation in operations)
    append_ledger(ledger, "FIXTURE_COMPLETED", fixture_class=args.mode, status="PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
