#!/usr/bin/env python3
"""Event-bound process identity observer for the V26 one-shot worker.

The observer subscribes to the Linux proc connector before the traced process
is created. Live ``/proc`` reads remain preferred, but an immutable fork event
is retained as a PID-reuse-resistant start identity for tasks that exit before
a polling read can complete. A trace identity is admissible only when exactly
one event/live identity, namespace identity, and temporal binding exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from workspace_boundary_v35 import guarded_append_jsonl, guarded_open_text
from transactional_telemetry_v35 import (
    TelemetryCompletionError,
    consume_completed_json,
    publish_json_transactionally,
)


EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
OBSERVER_IDENTITY = "V35_PROC_CONNECTOR_EVENT_BOUND_PROCESS_IDENTITY_OBSERVER_V1"
NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
NLMSG_DONE = 3
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_once(path: Path, value: Mapping[str, Any], fixture_identity: str) -> None:
    publish_json_transactionally(
        path,
        dict(value),
        producer_identity=OBSERVER_IDENTITY,
        fixture_identity=fixture_identity,
        schema_identity=str(value.get("record_type", "V35_OBSERVER_TELEMETRY")),
        operation_identity=f"TEMPORAL_OBSERVER_WRITE:{path.name}",
        generation="RUNTIME_OR_SELFTEST_0001",
    )


def append_event(path: Path, value: Mapping[str, Any]) -> None:
    guarded_append_jsonl(path, dict(value), operation_identity="TEMPORAL_OBSERVER_EVENT_APPEND", generation="RUNTIME_OR_SELFTEST_0001")


def parse_status(text: str) -> dict[str, list[int]]:
    wanted = {"Tgid", "Pid", "PPid", "NStgid", "NSpid", "Uid"}
    result: dict[str, list[int]] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in wanted:
            try:
                result[key] = [int(item) for item in value.split()]
            except ValueError:
                return {}
    return result


def parse_stat(text: str) -> tuple[int, int]:
    closing = text.rfind(")")
    if closing < 0:
        raise ValueError("missing comm terminator")
    fields = text[closing + 2 :].split()
    if len(fields) <= 19:
        raise ValueError("short proc stat")
    return int(fields[1]), int(fields[19])


def namespace_id(base: Path, name: str) -> str | None:
    try:
        return os.readlink(base / "ns" / name)
    except OSError:
        return None


def executable_identity(base: Path, exe_path: str) -> dict[str, Any] | None:
    try:
        info = (base / "exe").stat()
    except OSError:
        return None
    material = {"path": exe_path, "device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IFMT(info.st_mode)}
    return {**material, "identity_sha256": canonical_digest(material)}


def capture_task(process_id: int, task_id: int) -> dict[str, Any] | None:
    base = Path(f"/proc/{process_id}/task/{task_id}")
    before_mono = time.monotonic_ns()
    before_real = time.time_ns()
    try:
        fields = parse_status((base / "status").read_text(encoding="utf-8", errors="replace"))
        host_pid = fields["Pid"][0]
        host_tgid = fields["Tgid"][0]
        kernel_ppid, starttime = parse_stat((base / "stat").read_text(encoding="ascii", errors="strict"))
        local_pid = fields["NSpid"][-1]
        local_tgid = fields["NStgid"][-1]
        pid_ns = namespace_id(base, "pid")
        mount_ns = namespace_id(base, "mnt")
        exe_path = os.readlink(base / "exe")
        cmdline = [item.decode("utf-8", errors="replace") for item in (base / "cmdline").read_bytes().split(b"\0") if item]
        exe_id = executable_identity(base, exe_path)
    except (KeyError, OSError, IndexError, ValueError, UnicodeDecodeError):
        return None
    after_mono = time.monotonic_ns()
    after_real = time.time_ns()
    start_identity = f"PROC_STAT_STARTTIME:{starttime}"
    stable = {"host_pid": host_pid, "process_start_identity": start_identity, "pid_namespace_identity": pid_ns}
    record: dict[str, Any] = {
        "trace_file_pid": host_pid,
        "host_pid": host_pid,
        "local_pid": local_pid,
        "host_thread_group_id": host_tgid,
        "local_thread_group_id": local_tgid,
        "kernel_ppid": kernel_ppid,
        "parent_host_pid": None,
        "parent_local_pid": None,
        "parent_relation": None,
        "namespace_id": pid_ns,
        "pid_namespace_identity": pid_ns,
        "mount_namespace": mount_ns,
        "proc_starttime": starttime,
        "process_start_identity": start_identity,
        "process_start_identity_kind": "LIVE_PROC_STAT_STARTTIME",
        "proc_topology_identity": canonical_digest(stable),
        "stable_identity_tuple": [host_pid, start_identity, pid_ns],
        "exe": exe_path,
        "executable_identity": exe_id,
        "cmdline": cmdline,
        "observation_source": "HOST_PROC_TASK_LIVE_READ",
        "identity_capture_attempted": True,
        "identity_capture_result": "LIVE_PROC_CAPTURED",
        "first_observed_at_monotonic_ns": before_mono,
        "last_observed_at_monotonic_ns": after_mono,
        "first_observed_at_realtime_ns": before_real,
        "last_observed_at_realtime_ns": after_real,
        "observation_count": 1,
    }
    if host_pid == host_tgid and (exe_path.endswith("/codex") or (cmdline and cmdline[0].endswith("/bin/codex"))):
        try:
            mountinfo = (base / "mountinfo").read_text(encoding="utf-8", errors="strict")
            record["mountinfo_text"] = mountinfo
            record["mountinfo_sha256"] = hashlib.sha256(mountinfo.encode()).hexdigest()
        except OSError:
            pass
    return record


class ProcConnector:
    """Minimal read-only CN_PROC subscriber; no external dependency or target I/O."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        self.socket.bind((os.getpid(), CN_IDX_PROC))
        self.socket.setblocking(False)
        self._set_subscription(PROC_CN_MCAST_LISTEN)

    def _set_subscription(self, operation: int) -> None:
        payload = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0) + struct.pack("=I", operation)
        header = struct.pack("=IHHII", 16 + len(payload), NLMSG_DONE, 0, 1, os.getpid())
        self.socket.send(header + payload)

    def close(self) -> None:
        try:
            self._set_subscription(PROC_CN_MCAST_IGNORE)
        except OSError:
            pass
        self.socket.close()

    def drain(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            try:
                data = self.socket.recv(1 << 20)
            except BlockingIOError:
                break
            offset = 0
            while offset + 16 <= len(data):
                length, _kind, _flags, _sequence, _pid = struct.unpack_from("=IHHII", data, offset)
                if length < 16 or offset + length > len(data):
                    break
                body = data[offset + 16 : offset + length]
                if len(body) >= 36:
                    _index, _value, _seq, _ack, payload_length, _cn_flags = struct.unpack_from("=IIIIHH", body, 0)
                    payload = body[20 : 20 + payload_length]
                    if len(payload) >= 16:
                        what, cpu, timestamp_ns = struct.unpack_from("=IIQ", payload, 0)
                        if what == PROC_EVENT_FORK and len(payload) >= 32:
                            parent_pid, parent_tgid, child_pid, child_tgid = struct.unpack_from("=IIII", payload, 16)
                            events.append({"event": "PROC_CONNECTOR_FORK", "cpu": cpu, "event_timestamp_monotonic_ns": timestamp_ns, "parent_host_pid": parent_pid, "parent_host_tgid": parent_tgid, "child_host_pid": child_pid, "child_host_tgid": child_tgid})
                        elif what == PROC_EVENT_EXEC and len(payload) >= 24:
                            process_pid, process_tgid = struct.unpack_from("=II", payload, 16)
                            events.append({"event": "PROC_CONNECTOR_EXEC", "cpu": cpu, "event_timestamp_monotonic_ns": timestamp_ns, "host_pid": process_pid, "host_tgid": process_tgid})
                        elif what == PROC_EVENT_EXIT and len(payload) >= 40:
                            process_pid, process_tgid, exit_code, exit_signal, parent_pid, parent_tgid = struct.unpack_from("=IIIIII", payload, 16)
                            events.append({"event": "PROC_CONNECTOR_EXIT", "cpu": cpu, "event_timestamp_monotonic_ns": timestamp_ns, "host_pid": process_pid, "host_tgid": process_tgid, "exit_code": exit_code, "exit_signal": exit_signal, "parent_host_pid": parent_pid, "parent_host_tgid": parent_tgid})
                offset += (length + 3) & ~3
        return events


def trace_file_snapshot(trace_dir: Path) -> list[tuple[int, os.stat_result]]:
    result: list[tuple[int, os.stat_result]] = []
    for path in trace_dir.glob("trace.*"):
        try:
            trace_pid = int(path.name.rsplit(".", 1)[1])
            info = path.stat()
        except (OSError, ValueError, IndexError):
            continue
        result.append((trace_pid, info))
    return result


def connector_descendants(root_pid: int, fork_events: list[dict[str, Any]]) -> set[int]:
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for event in fork_events:
            parent = int(event["parent_host_pid"])
            child = int(event["child_host_pid"])
            if parent in descendants and child not in descendants:
                descendants.add(child)
                changed = True
    return descendants


def interval_distance(left_first: int, left_last: int, right_first: int, right_last: int) -> int:
    if left_first <= right_last and right_first <= left_last:
        return 0
    if left_last < right_first:
        return right_first - left_last
    return left_first - right_last


def first_exec_path(trace_path: Path) -> str | None:
    try:
        text = trace_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r'execve\("((?:[^"\\]|\\.)*)"', text)
    if match is None:
        return None
    return bytes(match.group(1), "utf-8").decode("unicode_escape", errors="replace")


def trace_timestamp_range(trace_path: Path) -> tuple[str | None, str | None]:
    """Return the first and last explicit strace timestamps without guessing."""

    try:
        lines = trace_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None, None
    timestamps = [
        match.group(1)
        for line in lines
        if (match := re.match(r"^([0-9]+\.[0-9]+)\s+", line)) is not None
    ]
    return (timestamps[0], timestamps[-1]) if timestamps else (None, None)


def typed_failure_reason(raw_reason: str | None) -> str:
    mapping = {
        "MISSING_OR_AMBIGUOUS_PROC_CONNECTOR_BIRTH": "TRACE_CORRELATION_FAILED",
        "TRACED_CREATION_EVENT_NOT_CORRELATED": "TRACE_CORRELATION_FAILED",
        "NEW_PID_NAMESPACE_REQUIRES_LIVE_NAMESPACE_CAPTURE": "NAMESPACE_IDENTITY_UNAVAILABLE",
        "PARENT_IDENTITY_OR_NAMESPACE_NOT_ESTABLISHED": "NAMESPACE_IDENTITY_UNAVAILABLE",
        "NO_ADMISSIBLE_IDENTITY_RECORD": "PROC_ENTRY_NOT_VISIBLE",
        "MULTIPLE_IDENTITY_GENERATIONS_OR_RECORDS": "TRACE_CORRELATION_FAILED",
    }
    return mapping.get(raw_reason or "", "UNKNOWN_EVIDENCE_BOUND_FAILURE")


def creation_flags_by_parent(trace_dir: Path, relevant_forks: list[dict[str, Any]]) -> dict[tuple[int, int], dict[str, Any]]:
    """Pair ordered CN_PROC births with ordered traced creation syscalls per parent."""
    result: dict[tuple[int, int], dict[str, Any]] = {}
    by_parent: dict[int, list[dict[str, Any]]] = {}
    for event in relevant_forks:
        by_parent.setdefault(int(event["parent_host_pid"]), []).append(event)
    for parent, connector_rows in by_parent.items():
        path = trace_dir / f"trace.{parent}"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        traced: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        for line in lines:
            start = re.match(r"(?P<ts>[0-9]+\.[0-9]+)\s+(?P<body>.*)", line)
            body = start.group("body") if start else line
            timestamp = start.group("ts") if start else None
            call = re.match(r"(?P<name>clone3?|fork|vfork)\((?P<args>.*)", body)
            if call and "<unfinished ...>" in body:
                pending.append({"syscall": call.group("name"), "args": call.group("args"), "trace_realtime": timestamp})
                continue
            if call:
                returned = re.search(r"\)\s+=\s+(?P<result>[0-9]+)(?:\s|$)", body)
                if returned:
                    traced.append({"syscall": call.group("name"), "args": call.group("args"), "local_child_pid": int(returned.group("result")), "trace_realtime": timestamp})
                continue
            resumed = re.match(r"<\.\.\.\s+(?P<name>clone3?|fork|vfork)\s+resumed>.*\)\s+=\s+(?P<result>[0-9]+)", body)
            if resumed:
                prior_index = next((index for index in range(len(pending) - 1, -1, -1) if pending[index]["syscall"] == resumed.group("name")), None)
                prior = pending.pop(prior_index) if prior_index is not None else {"syscall": resumed.group("name"), "args": "UNKNOWN", "trace_realtime": timestamp}
                traced.append({**prior, "local_child_pid": int(resumed.group("result"))})
        connector_rows.sort(key=lambda row: int(row["event_timestamp_monotonic_ns"]))
        for event, trace_event in zip(connector_rows, traced, strict=False):
            result[(parent, int(event["child_host_pid"]))] = trace_event
    return result


def add_or_refresh(observations: dict[tuple[int, str, str | None], dict[str, Any]], item: dict[str, Any]) -> None:
    key = (int(item["host_pid"]), str(item["process_start_identity"]), item.get("pid_namespace_identity"))
    prior = observations.get(key)
    if prior is None:
        observations[key] = item
        return
    prior["last_observed_at_monotonic_ns"] = item["last_observed_at_monotonic_ns"]
    prior["last_observed_at_realtime_ns"] = item["last_observed_at_realtime_ns"]
    prior["observation_count"] = int(prior.get("observation_count", 0)) + 1
    for field in ("mountinfo_text", "mountinfo_sha256"):
        if field in item and field not in prior:
            prior[field] = item[field]


def synthesize_event_bound_records(observations: dict[tuple[int, str, str | None], dict[str, Any]], trace_observations: Mapping[int, Mapping[str, Any]], fork_events: list[dict[str, Any]], trace_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_host: dict[int, list[dict[str, Any]]] = {}
    for row in observations.values():
        by_host.setdefault(int(row["host_pid"]), []).append(row)
    relevant = [event for event in fork_events if int(event["child_host_pid"]) in trace_observations]
    trace_creation = creation_flags_by_parent(trace_dir, relevant)
    unresolved = set(trace_observations) - set(by_host)
    failures: list[dict[str, Any]] = []
    progress = True
    while unresolved and progress:
        progress = False
        for host_pid in sorted(tuple(unresolved)):
            births = [event for event in relevant if int(event["child_host_pid"]) == host_pid]
            if len(births) != 1:
                failures.append({"trace_file_pid": host_pid, "reason": "MISSING_OR_AMBIGUOUS_PROC_CONNECTOR_BIRTH", "birth_event_count": len(births)})
                unresolved.remove(host_pid)
                continue
            birth = births[0]
            parent_host = int(birth["parent_host_pid"])
            parents = by_host.get(parent_host, [])
            if len(parents) != 1:
                continue
            parent = parents[0]
            creation = trace_creation.get((parent_host, host_pid))
            if creation is None:
                failures.append({"trace_file_pid": host_pid, "reason": "TRACED_CREATION_EVENT_NOT_CORRELATED"})
                unresolved.remove(host_pid)
                continue
            if "CLONE_NEWPID" in str(creation.get("args")):
                failures.append({"trace_file_pid": host_pid, "reason": "NEW_PID_NAMESPACE_REQUIRES_LIVE_NAMESPACE_CAPTURE"})
                unresolved.remove(host_pid)
                continue
            namespace = parent.get("pid_namespace_identity")
            if not isinstance(namespace, str):
                continue
            start_identity = f"PROC_CONNECTOR_FORK_EVENT:{birth['event_timestamp_monotonic_ns']}:{parent_host}:{host_pid}"
            exe_path = first_exec_path(trace_dir / f"trace.{host_pid}") or parent.get("exe")
            exe_id = ({"path": exe_path, "identity_sha256": canonical_digest({"path": exe_path, "trace_file_pid": host_pid, "start_identity": start_identity})} if isinstance(exe_path, str) else parent.get("executable_identity"))
            trace = trace_observations[host_pid]
            first = int(birth["event_timestamp_monotonic_ns"])
            last = max(first, int(trace["last_observed_at_monotonic_ns"]))
            local_child = creation.get("local_child_pid")
            stable = {"host_pid": host_pid, "process_start_identity": start_identity, "pid_namespace_identity": namespace}
            record: dict[str, Any] = {
                "trace_file_pid": host_pid, "host_pid": host_pid, "local_pid": local_child,
                "host_thread_group_id": int(birth["child_host_tgid"]),
                "local_thread_group_id": local_child if int(birth["child_host_pid"]) == int(birth["child_host_tgid"]) else parent.get("local_thread_group_id"),
                "kernel_ppid": parent_host, "parent_host_pid": parent_host, "parent_local_pid": parent.get("local_pid"),
                "parent_relation": "PROC_CONNECTOR_FORK_EVENT", "namespace_id": namespace,
                "pid_namespace_identity": namespace, "mount_namespace": parent.get("mount_namespace"), "proc_starttime": None,
                "process_start_identity": start_identity, "process_start_identity_kind": "PROC_CONNECTOR_FORK_EVENT_EXACT_EQUIVALENT",
                "proc_topology_identity": canonical_digest(stable), "stable_identity_tuple": [host_pid, start_identity, namespace],
                "exe": exe_path, "executable_identity": exe_id, "cmdline": [],
                "observation_source": "LINUX_PROC_CONNECTOR_FORK_EVENT_PLUS_TRACED_CREATION",
                "identity_capture_attempted": True, "identity_capture_result": "EVENT_BOUND_EXACT_EQUIVALENT_AFTER_LIVE_PROC_MISS",
                "live_proc_capture_failure_reason": "PROCESS_EXITED_OR_TASK_NOT_READABLE_BEFORE_PROC_CAPTURE",
                "first_observed_at_monotonic_ns": first, "last_observed_at_monotonic_ns": last,
                "first_observed_at_realtime_ns": None, "last_observed_at_realtime_ns": None,
                "observation_count": 1, "traced_creation_event": creation,
            }
            observations[(host_pid, start_identity, namespace)] = record
            by_host.setdefault(host_pid, []).append(record)
            unresolved.remove(host_pid)
            progress = True
    for host_pid in sorted(unresolved):
        failures.append({"trace_file_pid": host_pid, "reason": "PARENT_IDENTITY_OR_NAMESPACE_NOT_ESTABLISHED"})
    return list(observations.values()), failures


def enrich_final_observations(observations: list[dict[str, Any]], trace_observations: Mapping[int, Mapping[str, Any]], max_slack_ns: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_host: dict[int, list[dict[str, Any]]] = {}
    for item in observations:
        by_host.setdefault(int(item["host_pid"]), []).append(item)
    reuse_events = [{"host_pid": pid, "stable_identity_count": len(items), "stable_identities": [row["stable_identity_tuple"] for row in items]} for pid, items in by_host.items() if len(items) > 1]
    for item in observations:
        host_pid = int(item["host_pid"])
        if item.get("parent_host_pid") is None:
            host_tgid = int(item["host_thread_group_id"])
            item["parent_host_pid"] = host_tgid if host_pid != host_tgid else int(item["kernel_ppid"])
            item["parent_relation"] = "THREAD_GROUP" if host_pid != host_tgid else "PROCESS_PARENT"
        parent_candidates = by_host.get(int(item["parent_host_pid"]), [])
        parent = parent_candidates[0] if len(parent_candidates) == 1 else None
        if item.get("parent_local_pid") is None and parent is not None and parent.get("namespace_id") == item.get("namespace_id"):
            item["parent_local_pid"] = parent.get("local_pid")
        item["observation_timestamp_monotonic_ns"] = item["first_observed_at_monotonic_ns"]
        trace = trace_observations.get(host_pid)
        if trace is not None:
            distance = interval_distance(int(item["first_observed_at_monotonic_ns"]), int(item["last_observed_at_monotonic_ns"]), int(trace["first_observed_at_monotonic_ns"]), int(trace["last_observed_at_monotonic_ns"]))
            item["trace_event_timestamp_or_bounded_interval"] = {"source": "PROC_CONNECTOR_OR_LIVE_PROC_TO_TRACE_FILE_LIFETIME", "first_observed_at_monotonic_ns": trace["first_observed_at_monotonic_ns"], "last_observed_at_monotonic_ns": trace["last_observed_at_monotonic_ns"], "interval_distance_ns": distance, "max_correlation_slack_ns": max_slack_ns}
            item["temporal_binding_status"] = "PASS" if distance <= max_slack_ns else "FAIL_CLOSED"
        else:
            item["trace_event_timestamp_or_bounded_interval"] = None
            item["temporal_binding_status"] = "NOT_TRACE_RELEVANT"
        material = {key: value for key, value in item.items() if key not in {"immutable_record_digest", "mountinfo_text"}}
        item["immutable_record_digest"] = canonical_digest(material)
    return observations, reuse_events


def coverage_accounting(observations: list[dict[str, Any]], traces: Mapping[int, Mapping[str, Any]], synthesis_failures: list[dict[str, Any]]) -> dict[str, Any]:
    by_trace: dict[int, list[dict[str, Any]]] = {}
    for row in observations:
        if int(row["host_pid"]) in traces:
            by_trace.setdefault(int(row["host_pid"]), []).append(row)
    missing: list[int] = []
    ambiguous: list[int] = []
    valid: list[int] = []
    details: list[dict[str, Any]] = []
    failure_by_pid = {int(row["trace_file_pid"]): row for row in synthesis_failures}
    for trace_pid in sorted(traces):
        rows = by_trace.get(trace_pid, [])
        admissible = [row for row in rows if row.get("temporal_binding_status") == "PASS" and isinstance(row.get("pid_namespace_identity"), str) and isinstance(row.get("process_start_identity"), str) and row.get("stable_identity_tuple") == [trace_pid, row.get("process_start_identity"), row.get("pid_namespace_identity")]]
        selected = admissible[0] if len(admissible) == 1 else (rows[0] if len(rows) == 1 else None)
        if len(admissible) == 1:
            valid.append(trace_pid); outcome = "VALID_TEMPORAL_IDENTITY_RECORD"; reason = None
        elif len(admissible) > 1 or len(rows) > 1:
            ambiguous.append(trace_pid); outcome = "AMBIGUOUS_TEMPORAL_IDENTITY_RECORD"; reason = "TRACE_CORRELATION_FAILED"
        else:
            missing.append(trace_pid); outcome = "MISSING_TEMPORAL_IDENTITY_RECORD"; reason = typed_failure_reason(failure_by_pid.get(trace_pid, {}).get("reason", "NO_ADMISSIBLE_IDENTITY_RECORD"))
        trace = traces[trace_pid]
        details.append({
            "trace_identity": f"STRACE_FILE_PID:{trace_pid}",
            "trace_file_pid": trace_pid,
            "host_pid": selected.get("host_pid") if selected else trace_pid,
            "trace_first_timestamp": trace.get("trace_first_timestamp"),
            "trace_last_timestamp": trace.get("trace_last_timestamp"),
            "trace_first_observed_monotonic_ns": trace["first_observed_at_monotonic_ns"],
            "trace_last_observed_monotonic_ns": trace["last_observed_at_monotonic_ns"],
            "identity_capture_attempted": True,
            "identity_capture_attempt_timestamp_monotonic_ns": (
                selected.get("first_observed_at_monotonic_ns") if selected else trace["first_observed_at_monotonic_ns"]
            ),
            "proc_lookup_result": (
                "CAPTURED_LIVE_PROC" if selected and selected.get("process_start_identity_kind") == "LIVE_PROC_STAT_STARTTIME"
                else "NOT_CAPTURED_LIVE_PROC_EVENT_BOUND_EQUIVALENT" if selected
                else "NOT_VISIBLE_OR_NOT_CORRELATED"
            ),
            "process_start_identity": selected.get("process_start_identity") if selected else None,
            "pid_namespace_identity": selected.get("pid_namespace_identity") if selected else None,
            "parent_host_pid": selected.get("parent_host_pid") if selected else None,
            "parent_relation": selected.get("parent_relation") if selected else None,
            "temporal_relationship": selected.get("trace_event_timestamp_or_bounded_interval") if selected else None,
            "capture_outcome": outcome,
            "mapping_result": outcome,
            "failure_reason": reason,
            "admissible_record_count": len(admissible),
            "candidate_record_count": len(rows),
        })
    total = len(traces)
    complete = len(valid) == total and not missing and not ambiguous
    return {
        "lineage_relevant_trace_identity_count": total,
        "identity_capture_attempt_count": len(details),
        "successful_capture_count": len(valid),
        "valid_temporal_identity_mapping_count": len(valid),
        "missing_identity_count": len(missing),
        "ambiguous_identity_count": len(ambiguous),
        "coverage_complete": complete,
        "valid_trace_identities": valid,
        "missing_trace_identities": missing,
        "ambiguous_trace_identities": ambiguous,
        "per_trace_capture_accounting": details,
        "percentage_thresholds": "PROHIBITED_AND_NOT_USED",
    }


def run(args: argparse.Namespace) -> int:
    events, snapshot, ready = Path(args.events), Path(args.snapshot), Path(args.ready)
    root_record, root_bound, stop, trace_dir = Path(args.root), Path(args.root_bound), Path(args.stop), Path(args.trace_dir)
    for path in (events, snapshot, ready, root_bound):
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"observer output already exists: {path}")
    with guarded_open_text(events, operation_identity="TEMPORAL_OBSERVER_EVENTS_CREATE", generation="RUNTIME_OR_SELFTEST_0001"):
        pass
    connector = ProcConnector()
    ready_record = {"record_type": "TEMPORAL_PROCESS_IDENTITY_OBSERVER_READINESS", "execution_identity": EXECUTION_IDENTITY, "observer_identity": OBSERVER_IDENTITY, "state": "OBSERVER_READY", "capture_mechanism": "LINUX_PROC_CONNECTOR_PLUS_LIVE_PROC_AND_TRACE_CORRELATION", "proc_connector_subscription": "ACTIVE_BEFORE_TRACED_PROCESS_CREATION", "observer_pid": os.getpid(), "ready_monotonic_ns": time.monotonic_ns(), "ready_realtime_ns": time.time_ns(), "clock_semantics": "CLOCK_MONOTONIC_NS_AND_CLOCK_REALTIME_NS", "poll_interval_ns": args.poll_interval_ns, "max_correlation_slack_ns": args.max_correlation_slack_ns}
    write_once(ready, ready_record, args.fixture_identity); append_event(events, ready_record)
    observations: dict[tuple[int, str, str | None], dict[str, Any]] = {}
    trace_observations: dict[int, dict[str, Any]] = {}
    connector_events: list[dict[str, Any]] = []
    fork_events: list[dict[str, Any]] = []
    root_pid: int | None = None
    root_bound_emitted = False
    scan_count = 0
    try:
        while True:
            for event in connector.drain():
                connector_events.append(event)
                if event["event"] == "PROC_CONNECTOR_FORK":
                    fork_events.append(event)
                    captured = capture_task(int(event["child_host_tgid"]), int(event["child_host_pid"]))
                    if captured is not None:
                        captured["proc_connector_birth_event"] = event
                        add_or_refresh(observations, captured)
            if root_pid is None:
                try:
                    root_payload = consume_completed_json(
                        root_record,
                        expected_producer_identity="V35_RUNNER",
                        expected_fixture_identity=args.fixture_identity,
                        expected_schema_identity="V35_OBSERVER_ROOT",
                    )
                except TelemetryCompletionError:
                    root_payload = None
                if root_payload is not None:
                    root_pid = int(root_payload["root_pid"])
                    append_event(events, {"event": "ROOT_IDENTITY_RECEIVED", "root_pid": root_pid, "monotonic_ns": time.monotonic_ns(), "realtime_ns": time.time_ns()})
            now_mono, now_real = time.monotonic_ns(), time.time_ns()
            for trace_pid, info in trace_file_snapshot(trace_dir):
                row = trace_observations.get(trace_pid)
                if row is None:
                    trace_observations[trace_pid] = {"trace_file_pid": trace_pid, "first_observed_at_monotonic_ns": now_mono, "last_observed_at_monotonic_ns": now_mono, "first_observed_at_realtime_ns": now_real, "last_observed_at_realtime_ns": now_real, "first_size": info.st_size, "last_size": info.st_size, "last_mtime_ns": info.st_mtime_ns}
                else:
                    row.update({"last_observed_at_monotonic_ns": now_mono, "last_observed_at_realtime_ns": now_real, "last_size": info.st_size, "last_mtime_ns": info.st_mtime_ns})
                item = capture_task(trace_pid, trace_pid)
                if item is not None:
                    add_or_refresh(observations, item)
            if root_pid is not None:
                descendants = connector_descendants(root_pid, fork_events)
                for process_id in descendants:
                    task_root = Path(f"/proc/{process_id}/task")
                    try:
                        task_ids = [int(entry.name) for entry in os.scandir(task_root) if entry.name.isdigit()]
                    except OSError:
                        continue
                    for task_id in task_ids:
                        item = capture_task(process_id, task_id)
                        if item is not None:
                            add_or_refresh(observations, item)
                if not root_bound_emitted and any(int(row["host_pid"]) == root_pid for row in observations.values()):
                    bound = {"record_type": "TEMPORAL_PROCESS_IDENTITY_OBSERVER_ROOT_BINDING", "execution_identity": EXECUTION_IDENTITY, "observer_identity": OBSERVER_IDENTITY, "state": "OBSERVER_ROOT_BOUND", "root_pid": root_pid, "bound_monotonic_ns": time.monotonic_ns(), "bound_realtime_ns": time.time_ns()}
                    write_once(root_bound, bound, args.fixture_identity); append_event(events, bound); root_bound_emitted = True
            scan_count += 1
            try:
                stop_payload = consume_completed_json(
                    stop,
                    expected_producer_identity="V35_RUNNER",
                    expected_fixture_identity=args.fixture_identity,
                    expected_schema_identity="V35_OBSERVER_STOP",
                )
            except TelemetryCompletionError:
                stop_payload = None
            if stop_payload is not None:
                for event in connector.drain():
                    connector_events.append(event)
                    if event["event"] == "PROC_CONNECTOR_FORK":
                        fork_events.append(event)
                break
            if args.poll_interval_ns:
                time.sleep(args.poll_interval_ns / 1_000_000_000)
    finally:
        connector.close()
    relevant_pids = connector_descendants(root_pid, fork_events) if root_pid is not None else set()
    relevant_forks = [event for event in fork_events if int(event["child_host_pid"]) in relevant_pids]
    for trace_pid, trace in trace_observations.items():
        first_timestamp, last_timestamp = trace_timestamp_range(trace_dir / f"trace.{trace_pid}")
        trace["trace_first_timestamp"] = first_timestamp
        trace["trace_last_timestamp"] = last_timestamp
    all_records, synthesis_failures = synthesize_event_bound_records(observations, trace_observations, relevant_forks, trace_dir)
    final, reuse_events = enrich_final_observations(all_records, trace_observations, args.max_correlation_slack_ns)
    coverage = coverage_accounting(final, trace_observations, synthesis_failures)
    snapshot_status = "PASS" if root_bound_emitted and coverage["coverage_complete"] else "FAIL_CLOSED_INCOMPLETE_TEMPORAL_IDENTITY_COVERAGE"
    snapshot_record = {"record_type": "V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT", "execution_identity": EXECUTION_IDENTITY, "observer_identity": OBSERVER_IDENTITY, "status": snapshot_status, "diagnostic_complete": True, "observer_runtime_completion_state": "OBSERVER_COMPLETED_PASS" if snapshot_status == "PASS" else "OBSERVER_COMPLETED_FAIL_CLOSED", "observer_exit_code": 0 if snapshot_status == "PASS" else 1, "observer_exit_reason": "COMPLETE_N_OF_N_COVERAGE" if snapshot_status == "PASS" else "INCOMPLETE_N_OF_N_TEMPORAL_IDENTITY_COVERAGE", "state_sequence": ["OBSERVER_CREATED", "PROC_CONNECTOR_SUBSCRIBED", "OBSERVER_READY", "OBSERVER_ROOT_BOUND" if root_bound_emitted else "OBSERVER_ROOT_UNBOUND", "OBSERVER_STOPPED"], "root_pid": root_pid, "scan_count": scan_count, "process_observation_count": len(final), "process_observations": final, "trace_file_observation_count": len(trace_observations), "trace_file_observations": [trace_observations[key] for key in sorted(trace_observations)], "independently_enumerated_trace_visible_identities": sorted(trace_observations), "relevant_proc_connector_event_count": sum(1 for row in connector_events if row.get("host_pid") in relevant_pids or row.get("child_host_pid") in relevant_pids), "relevant_proc_connector_fork_events": relevant_forks, "identity_synthesis_failures": synthesis_failures, "pid_reuse_event_count": len(reuse_events), "pid_reuse_events": reuse_events, "coverage_accounting": coverage, "clock_semantics": "CLOCK_MONOTONIC_NS_AND_CLOCK_REALTIME_NS", "poll_interval_ns": args.poll_interval_ns, "max_correlation_slack_ns": args.max_correlation_slack_ns, "stopped_monotonic_ns": time.monotonic_ns(), "stopped_realtime_ns": time.time_ns()}
    write_once(snapshot, snapshot_record, args.fixture_identity)
    append_event(events, {"event": "OBSERVER_STOPPED", "snapshot_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(), "coverage_complete": coverage["coverage_complete"], "monotonic_ns": time.monotonic_ns()})
    return 0 if snapshot_record["status"] == "PASS" else 1


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--events", required=True)
    value.add_argument("--snapshot", required=True)
    value.add_argument("--ready", required=True)
    value.add_argument("--root", required=True)
    value.add_argument("--root-bound", required=True)
    value.add_argument("--stop", required=True)
    value.add_argument("--trace-dir", required=True)
    value.add_argument("--fixture-identity", required=True)
    value.add_argument("--poll-interval-ns", type=int, default=100_000)
    value.add_argument("--max-correlation-slack-ns", type=int, default=2_000_000_000)
    return value


if __name__ == "__main__":
    parsed = parser().parse_args()
    try:
        raise SystemExit(run(parsed))
    except SystemExit:
        raise
    except Exception as exc:  # typed failure completeness is part of the V26 contract
        snapshot_path = Path(parsed.snapshot)
        diagnostic = {
            "record_type": "V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT",
            "execution_identity": EXECUTION_IDENTITY,
            "observer_identity": OBSERVER_IDENTITY,
            "status": "FAIL_CLOSED_OBSERVER_INTERNAL_ERROR",
            "diagnostic_complete": True,
            "observer_runtime_completion_state": "OBSERVER_ABORTED_FAIL_CLOSED",
            "observer_exit_code": 2,
            "observer_exit_reason": "OBSERVER_INTERNAL_ERROR",
            "failure_envelope": {
                "fixture_identity": parsed.fixture_identity,
                "observer_exit_code": 2,
                "failure_stage": "OBSERVER_EXECUTION",
                "failure_reason": f"{type(exc).__name__}:{exc}",
                "classification": "OBSERVER_EXECUTION_FAILURE",
                "telemetry_complete": False,
                "raw_output_sha256": hashlib.sha256(Path(parsed.events).read_bytes() if Path(parsed.events).is_file() else b"").hexdigest(),
                "raw_output_bytes": Path(parsed.events).stat().st_size if Path(parsed.events).is_file() else 0,
                "available_counters": {
                    "trace_denominator": None,
                    "capture_count": None,
                    "valid_mapping_count": None,
                    "missing_mapping_count": None,
                    "ambiguous_mapping_count": None
                }
            },
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "coverage_accounting": {
                "lineage_relevant_trace_identity_count": 0,
                "identity_capture_attempt_count": 0,
                "successful_capture_count": 0,
                "valid_temporal_identity_mapping_count": 0,
                "missing_identity_count": 0,
                "ambiguous_identity_count": 0,
                "coverage_complete": False,
                "per_trace_capture_accounting": [],
                "percentage_thresholds": "PROHIBITED_AND_NOT_USED",
            },
        }
        if not snapshot_path.exists() and not snapshot_path.is_symlink():
            write_once(snapshot_path, diagnostic, parsed.fixture_identity)
        print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
