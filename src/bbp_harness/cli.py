from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .adapters.codex_cli import CodexCliRuntime
from .candidates import CandidateStateMachine
from .config import HarnessPaths, load_config
from .db import Database
from .evals import EvaluationSuite
from .knowledge import KnowledgeIndex
from .orchestrator import Orchestrator
from .scope import ScopeError, load_scope
from .util import pretty_json, utcnow


def _runtime() -> tuple[HarnessPaths, Database, Orchestrator]:
    paths = HarnessPaths.discover()
    paths.ensure()
    database = Database(paths.database)
    database.migrate()
    config = load_config(paths)
    return paths, database, Orchestrator(database, paths, config)


def _target(value: str | None) -> Path:
    return Path(value or os.getcwd()).expanduser().resolve()


def _campaign(orchestrator: Orchestrator, target: Path, explicit: str | None) -> str:
    return explicit or orchestrator.current_campaign(target)


def _print(value: Any) -> None:
    if isinstance(value, str):
        print(value)
    else:
        print(pretty_json(value), end="")


def cmd_init(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    _print(orchestrator.initialize_target(_target(args.target)))
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    target = _target(args.target)
    try:
        scope = load_scope(target, require_confirmed=True)
    except ScopeError as exc:
        _print({"status": "BLOCKED_SCOPE", "target": str(target), "reasons": exc.reasons})
        return 2
    _print({"status": "PASS", "target": str(target), "scope": scope.to_record()})
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    if not args.new:
        try:
            campaign_id = orchestrator.current_campaign(target)
            current = orchestrator.status(campaign_id)
            if current["campaign"]["status"] in {"ACTIVE", "BLOCKED", "PAUSED"}:
                _print({"reused": True, **current})
                return 0
        except (KeyError, FileNotFoundError, json.JSONDecodeError):
            pass
    try:
        result = orchestrator.start_campaign(
            target,
            args.objective,
            novel_discovery_mode=args.novel_discovery,
            max_waves=args.max_waves,
        )
    except ScopeError as exc:
        _print(
            {
                "status": "BLOCKED_SCOPE",
                "target": str(target),
                "scope_file": str(target / ".bbpresearch" / "scope.yaml"),
                "reasons": exc.reasons,
            }
        )
        return 2
    _print(result)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    campaign_id = _campaign(orchestrator, target, args.campaign)
    result = orchestrator.run(campaign_id, max_waves=args.max_waves)
    _print(result)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    try:
        campaign_id = orchestrator.current_campaign(target)
        status = orchestrator.status(campaign_id)["campaign"]["status"]
        if status not in {"ACTIVE", "BLOCKED", "PAUSED"} or args.new:
            raise KeyError(campaign_id)
    except (KeyError, FileNotFoundError, json.JSONDecodeError):
        try:
            started = orchestrator.start_campaign(
                target,
                args.objective,
                novel_discovery_mode=args.novel_discovery,
                max_waves=args.max_waves,
            )
        except ScopeError as exc:
            _print(
                {
                    "status": "BLOCKED_SCOPE",
                    "target": str(target),
                    "scope_file": str(target / ".bbpresearch" / "scope.yaml"),
                    "reasons": exc.reasons,
                }
            )
            return 2
        campaign_id = started["campaign_id"]
    with orchestrator.database.connect() as connection:
        connection.execute(
            "UPDATE campaigns SET status='ACTIVE', updated_at=? WHERE id=? AND status IN ('BLOCKED','PAUSED')",
            (utcnow(), campaign_id),
        )
    _print(orchestrator.run(campaign_id, max_waves=args.max_waves))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    campaign_id = _campaign(orchestrator, target, args.campaign)
    _print(orchestrator.status(campaign_id))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    _print(CandidateStateMachine(database).explain(args.candidate_id))
    return 0


def cmd_focus(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    campaign_id = _campaign(orchestrator, target, args.campaign)
    job_id = orchestrator.focus(campaign_id, args.lane, args.question)
    with orchestrator.database.connect() as connection:
        connection.execute("UPDATE campaigns SET status='ACTIVE', updated_at=? WHERE id=?", (utcnow(), campaign_id))
    _print({"campaign_id": campaign_id, "job_id": job_id, "lane": args.lane, "status": "READY"})
    return 0


def cmd_stop_lane(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    campaign_id = _campaign(orchestrator, target, args.campaign)
    count = orchestrator.stop_lane(campaign_id, args.lane, args.reason)
    _print({"campaign_id": campaign_id, "lane": args.lane, "jobs_cancelled": count})
    return 0


def cmd_abort(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    target = _target(args.target)
    campaign_id = _campaign(orchestrator, target, args.campaign)
    _print(orchestrator.abort_campaign(campaign_id, args.reason))
    return 0


def cmd_pause(args: argparse.Namespace) -> int:
    _, database, orchestrator = _runtime()
    campaign_id = _campaign(orchestrator, _target(args.target), args.campaign)
    with database.connect() as connection:
        connection.execute(
            "UPDATE campaigns SET status='PAUSED', updated_at=? WHERE id=? AND status IN ('ACTIVE','BLOCKED')",
            (utcnow(), campaign_id),
        )
    _print({"campaign_id": campaign_id, "status": "PAUSED"})
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    _, database, orchestrator = _runtime()
    campaign_id = _campaign(orchestrator, _target(args.target), args.campaign)
    with database.connect() as connection:
        connection.execute(
            "UPDATE campaigns SET status='ACTIVE', updated_at=? WHERE id=? AND status IN ('PAUSED','BLOCKED')",
            (utcnow(), campaign_id),
        )
    _print(orchestrator.run(campaign_id, max_waves=args.max_waves))
    return 0


def cmd_manual_confirm(args: argparse.Namespace) -> int:
    _, _, orchestrator = _runtime()
    result = orchestrator.manual_confirm(
        args.candidate_id,
        attempts=args.attempts,
        successes=args.successes,
        evidence_uris=args.evidence,
        cleanup=args.cleanup,
    )
    _print(result)
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    paths, database, _ = _runtime()
    config = load_config(paths)
    index = KnowledgeIndex(database)
    roots = args.root or config.knowledge_roots
    reports = args.report_db or config.report_databases
    _print({"files": index.index_roots(roots), "reports": index.index_report_databases(reports)})
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    _print(KnowledgeIndex(database).query(args.query, top_k=args.top_k, max_chars=args.max_chars))
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    paths, database, _ = _runtime()
    _print({"database": str(paths.database), **database.summary()})
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    paths, database, _ = _runtime()
    config = load_config(paths)
    runtime = CodexCliRuntime(
        config.codex_binary,
        execution_authorized=config.codex_runtime_execution_authorized,
    )
    runtime_identity = runtime.identity_report()
    skill_path = Path.home() / ".codex" / "skills" / "codex-security-harness" / "SKILL.md"
    checks = {
        "version": __version__,
        "database": str(paths.database),
        "database_integrity": database.integrity_check(),
        "codex_runtime": runtime_identity,
        "skill": str(skill_path),
        "skill_installed": skill_path.exists(),
        "config": str(paths.config_file),
    }
    checks["status"] = (
        "PASS"
        if runtime_identity.get("status") == "PASS_LOCKED_RUNTIME"
        and checks["database_integrity"] == "ok"
        and skill_path.exists()
        else "BLOCKED"
    )
    _print(checks)
    return 0 if checks["status"] == "PASS" else 1


def cmd_eval_import(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    _print(EvaluationSuite(database, __version__).import_manifest(Path(args.manifest).resolve()))
    return 0


def cmd_eval_start(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    run_id = EvaluationSuite(database, __version__).start(args.suite)
    _print({"eval_run_id": run_id, "suite": args.suite, "status": "RUNNING"})
    return 0


def cmd_eval_record(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    EvaluationSuite(database, __version__).record(
        args.run_id,
        args.case_id,
        observed_class=args.observed_class,
        found=args.found,
        reproduced=args.reproduced,
        correctly_triaged=args.correctly_triaged,
        false_positive=args.false_positive,
        elapsed_seconds=args.elapsed_seconds,
        token_cost=args.token_cost,
    )
    _print({"eval_run_id": args.run_id, "case_id": args.case_id, "status": "RECORDED"})
    return 0


def cmd_eval_score(args: argparse.Namespace) -> int:
    _, database, _ = _runtime()
    _print(EvaluationSuite(database, __version__).score(args.run_id, finalize=not args.no_finalize))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bbp-harness", description="Codex Security Harness control plane")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create .bbpresearch scope scaffold")
    init.add_argument("--target")
    init.set_defaults(func=cmd_init)

    scope = sub.add_parser("scope-check", help="validate target scope card")
    scope.add_argument("--target")
    scope.set_defaults(func=cmd_scope_check)

    start = sub.add_parser("start", help="initialize a campaign without running workers")
    start.add_argument("--target")
    start.add_argument("--objective", default="Find and validate in-scope security vulnerabilities")
    start.add_argument("--max-waves", type=int, default=4)
    start.add_argument("--novel-discovery", action="store_true")
    start.add_argument("--new", action="store_true")
    start.set_defaults(func=cmd_start)

    run = sub.add_parser("run", help="execute dependency-ready Codex workers")
    run.add_argument("--target")
    run.add_argument("--campaign")
    run.add_argument("--max-waves", type=int)
    run.set_defaults(func=cmd_run)

    audit = sub.add_parser("audit", help="start or resume an autonomous bounded campaign")
    audit.add_argument("--target")
    audit.add_argument("--objective", default="Find and validate in-scope security vulnerabilities")
    audit.add_argument("--max-waves", type=int, default=4)
    audit.add_argument("--novel-discovery", action="store_true")
    audit.add_argument("--new", action="store_true")
    audit.set_defaults(func=cmd_audit)

    status = sub.add_parser("status", help="show persistent campaign state")
    status.add_argument("--target")
    status.add_argument("--campaign")
    status.set_defaults(func=cmd_status)

    explain = sub.add_parser("explain", help="explain a candidate and its blockers")
    explain.add_argument("candidate_id")
    explain.set_defaults(func=cmd_explain)

    focus = sub.add_parser("focus", help="add an adaptive bounded research lane")
    focus.add_argument("lane")
    focus.add_argument("question")
    focus.add_argument("--target")
    focus.add_argument("--campaign")
    focus.set_defaults(func=cmd_focus)

    stop = sub.add_parser("stop-lane", help="stop queued work in a lane")
    stop.add_argument("lane")
    stop.add_argument("--reason", default="stopped by user")
    stop.add_argument("--target")
    stop.add_argument("--campaign")
    stop.set_defaults(func=cmd_stop_lane)

    abort = sub.add_parser("abort", help="cancel queued work and close a campaign")
    abort.add_argument("--reason", default="aborted by user")
    abort.add_argument("--target")
    abort.add_argument("--campaign")
    abort.set_defaults(func=cmd_abort)

    pause = sub.add_parser("pause", help="pause a campaign")
    pause.add_argument("--target")
    pause.add_argument("--campaign")
    pause.set_defaults(func=cmd_pause)

    resume = sub.add_parser("resume", help="recover stale leases and continue")
    resume.add_argument("--target")
    resume.add_argument("--campaign")
    resume.add_argument("--max-waves", type=int)
    resume.set_defaults(func=cmd_resume)

    confirm = sub.add_parser("manual-confirm", help="record the human reproduction gate")
    confirm.add_argument("candidate_id")
    confirm.add_argument("--attempts", type=int, required=True)
    confirm.add_argument("--successes", type=int, required=True)
    confirm.add_argument("--evidence", action="append", required=True, help="path to an immutable evidence file")
    confirm.add_argument("--cleanup", required=True)
    confirm.set_defaults(func=cmd_manual_confirm)

    index = sub.add_parser("index", help="index skills, prompts, agents, and report corpora")
    index.add_argument("--root", action="append")
    index.add_argument("--report-db", action="append")
    index.set_defaults(func=cmd_index)

    query = sub.add_parser("query", help="query the local knowledge index")
    query.add_argument("query")
    query.add_argument("--top-k", type=int, default=8)
    query.add_argument("--max-chars", type=int, default=1200)
    query.set_defaults(func=cmd_query)

    db = sub.add_parser("db", help="show database health and counts")
    db.set_defaults(func=cmd_db)

    doctor = sub.add_parser("doctor", help="verify installation")
    doctor.set_defaults(func=cmd_doctor)

    eval_import = sub.add_parser("eval-import", help="import a blinded evaluation manifest")
    eval_import.add_argument("manifest")
    eval_import.set_defaults(func=cmd_eval_import)

    eval_start = sub.add_parser("eval-start", help="start an evaluation run")
    eval_start.add_argument("suite")
    eval_start.set_defaults(func=cmd_eval_start)

    eval_record = sub.add_parser("eval-record", help="record one blinded case result")
    eval_record.add_argument("run_id")
    eval_record.add_argument("case_id")
    eval_record.add_argument("--observed-class", required=True)
    eval_record.add_argument("--found", action="store_true")
    eval_record.add_argument("--reproduced", action="store_true")
    eval_record.add_argument("--correctly-triaged", action="store_true")
    eval_record.add_argument("--false-positive", action="store_true")
    eval_record.add_argument("--elapsed-seconds", type=float, default=0)
    eval_record.add_argument("--token-cost", type=int, default=0)
    eval_record.set_defaults(func=cmd_eval_record)

    eval_score = sub.add_parser("eval-score", help="score an evaluation run without exposing truth to workers")
    eval_score.add_argument("run_id")
    eval_score.add_argument("--no-finalize", action="store_true")
    eval_score.set_defaults(func=cmd_eval_score)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ScopeError as exc:
        _print({"status": "BLOCKED_SCOPE", "reasons": exc.reasons})
        return 2
    except (KeyError, ValueError, FileNotFoundError, RuntimeError) as exc:
        _print({"status": "ERROR", "error": str(exc), "type": type(exc).__name__})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
