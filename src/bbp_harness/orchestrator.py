from __future__ import annotations

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Protocol

from .candidates import CandidateStateMachine, KILL_CODES
from .config import HarnessConfig, HarnessPaths
from .db import Database
from .evidence import EvidenceStore
from .fingerprint import fingerprint_target
from .ids import new_id
from .knowledge import KnowledgeIndex
from .scheduler import Scheduler
from .scope import SCOPE_TEMPLATE, ScopeCard, ScopeError, load_scope, scope_path
from .util import atomic_write_text, canonical_json, pretty_json, utcnow
from .workers import CodexWorkerRunner, WorkerResult


LANES = {
    "authority": "Authority/capability: principals, scopes, resource identity, lifecycle, confused deputy, and privilege transitions.",
    "representation": "Representation/consumer: parse, canonicalization, serialization, checked-versus-consumed identity, protocol grammar, and shared consumers.",
    "state": "State/composition: transitions, queues, retries, caches, races, lifecycle changes, and cross-feature composition.",
}


class Runner(Protocol):
    def run(self, **kwargs: Any) -> WorkerResult: ...


class WorkspaceManager:
    def __init__(self, paths: HarnessPaths):
        self.paths = paths

    def isolated_copy(self, target: Path, campaign_id: str, job_id: str) -> Path:
        root = (self.paths.workspaces_dir / campaign_id).resolve()
        root.mkdir(parents=True, exist_ok=True)
        workspace = (root / job_id).resolve()
        if root not in workspace.parents:
            raise ValueError("workspace path escaped managed root")
        if workspace.exists():
            return workspace
        is_git = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        ).returncode == 0
        if is_git:
            completed = subprocess.run(
                ["git", "clone", "--local", "--no-hardlinks", "--quiet", str(target), str(workspace)],
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"isolated git clone failed: {completed.stderr.strip()}")
        else:
            shutil.copytree(
                target,
                workspace,
                ignore=shutil.ignore_patterns(".bbpresearch", ".git", "node_modules", ".venv", "dist", "build"),
            )
        return workspace


class Orchestrator:
    def __init__(
        self,
        database: Database,
        paths: HarnessPaths,
        config: HarnessConfig,
        runner: Runner | None = None,
    ):
        self.database = database
        self.paths = paths
        self.config = config
        self.scheduler = Scheduler(database)
        self.candidates = CandidateStateMachine(database)
        self.knowledge = KnowledgeIndex(database)
        self.runner = runner or CodexWorkerRunner(database, paths, config)
        self.workspaces = WorkspaceManager(paths)

    def initialize_target(self, target: Path) -> dict[str, Any]:
        target = target.expanduser().resolve()
        if not target.is_dir():
            raise FileNotFoundError(target)
        research = target / ".bbpresearch"
        research.mkdir(parents=True, exist_ok=True)
        created: list[str] = []
        scope = research / "scope.yaml"
        if not scope.exists():
            template = json.loads(json.dumps(SCOPE_TEMPLATE))
            template["asset"]["name"] = target.name
            atomic_write_text(scope, pretty_json(template), mode=0o600)
            created.append(str(scope))
        instructions = research / "AGENTS.md"
        if not instructions.exists():
            atomic_write_text(
                instructions,
                "# Codex Security Harness campaign state\n\n"
                "Treat this directory as harness-owned research state. Do not edit the SQLite database "
                "or evidence records directly. Use `bbp-harness` commands. The target source remains "
                "read-only unless scope.yaml explicitly permits local tests in an isolated workspace.\n",
                mode=0o600,
            )
            created.append(str(instructions))
        gitignore = research / ".gitignore"
        if not gitignore.exists():
            atomic_write_text(gitignore, "*\n!.gitignore\n!scope.yaml\n!AGENTS.md\n", mode=0o644)
            created.append(str(gitignore))
        return {"target": str(target), "research_dir": str(research), "created": created, "scope": str(scope)}

    def start_campaign(
        self,
        target: Path,
        objective: str,
        *,
        novel_discovery_mode: bool = False,
        max_waves: int = 4,
    ) -> dict[str, Any]:
        target = target.expanduser().resolve()
        self.initialize_target(target)
        scope_card = load_scope(target, require_confirmed=True)
        fingerprint = fingerprint_target(target)
        campaign_id = new_id("CAM")
        now = utcnow()
        max_workers = min(
            int(scope_card.limits.get("max_concurrency", self.config.max_concurrency)),
            self.config.max_concurrency,
        )
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO targets(root_path, repo_url, repo_commit, branch, dirty, fingerprint_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(root_path) DO UPDATE SET
                    repo_url=excluded.repo_url,
                    repo_commit=excluded.repo_commit,
                    branch=excluded.branch,
                    dirty=excluded.dirty,
                    fingerprint_json=excluded.fingerprint_json,
                    updated_at=excluded.updated_at
                """,
                (
                    str(target),
                    fingerprint["git"]["remote"],
                    fingerprint["git"]["commit"],
                    fingerprint["git"]["branch"],
                    int(fingerprint["git"]["dirty"]),
                    canonical_json(fingerprint),
                    now,
                    now,
                ),
            )
            target_id = int(connection.execute("SELECT id FROM targets WHERE root_path=?", (str(target),)).fetchone()[0])
            connection.execute(
                """
                INSERT INTO campaigns(
                    id, target_id, objective, status, scope_status, novel_discovery_mode,
                    max_workers, max_waves, time_budget_minutes, token_budget,
                    started_at, created_at, updated_at
                ) VALUES(?,?,?,'ACTIVE','PROVEN',?,?,?,?,?,?,?,?)
                """,
                (
                    campaign_id,
                    target_id,
                    objective,
                    int(novel_discovery_mode),
                    max_workers,
                    max_waves,
                    scope_card.limits.get("time_budget_minutes"),
                    scope_card.limits.get("token_budget"),
                    now,
                    now,
                    now,
                ),
            )
            record = scope_card.to_record()
            connection.execute(
                """
                INSERT INTO scope(
                    campaign_id, source_path, scope_hash, authorization_confirmed,
                    program, asset, allowed_methods_json, exclusions_json,
                    rate_limits_json, stop_conditions_json, raw_json, verified_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    campaign_id,
                    record["source_path"],
                    record["scope_hash"],
                    1,
                    record["program"],
                    record["asset"],
                    canonical_json(record["allowed_methods"]),
                    canonical_json(record["exclusions"]),
                    canonical_json(record["rate_limits"]),
                    canonical_json(record["stop_conditions"]),
                    canonical_json(record["raw"]),
                    now,
                ),
            )
            self.database.event(
                campaign_id,
                "campaign",
                campaign_id,
                "CAMPAIGN_INITIALIZED",
                {"objective": objective, "target": str(target), "scope_hash": scope_card.digest},
                connection,
            )
        mapper_job = self.scheduler.create_job(
            campaign_id,
            "mapper",
            lane="mapping",
            priority=0,
            input_data={"objective": objective, "target_fingerprint": fingerprint},
            max_attempts=self.config.max_worker_attempts,
        )
        marker = target / ".bbpresearch" / "campaign.json"
        atomic_write_text(
            marker,
            pretty_json({"active_campaign_id": campaign_id, "database": str(self.database.path), "updated_at": now}),
            mode=0o600,
        )
        return {
            "campaign_id": campaign_id,
            "target": str(target),
            "commit": fingerprint["git"]["commit"],
            "scope": "PASS",
            "fingerprint": fingerprint,
            "mapper_job": mapper_job,
            "max_workers": max_workers,
            "max_waves": max_waves,
        }

    def run(self, campaign_id: str, max_waves: int | None = None) -> dict[str, Any]:
        campaign = self._campaign(campaign_id)
        if campaign["status"] not in {"ACTIVE", "BLOCKED"}:
            raise ValueError(f"campaign is not runnable: {campaign['status']}")
        self.scheduler.reset_stale_leases(self.config.stale_lease_seconds)
        wave_limit = max_waves if max_waves is not None else int(campaign["max_waves"])
        wave_summaries: list[dict[str, Any]] = []
        for wave_number in range(1, wave_limit + 1):
            self.scheduler.refresh(campaign_id)
            campaign = self._campaign(campaign_id)
            jobs = self.scheduler.claim_ready(campaign_id, int(campaign["max_workers"]))
            if not jobs:
                break
            results: list[WorkerResult] = []
            with ThreadPoolExecutor(max_workers=int(campaign["max_workers"]), thread_name_prefix="bbp-worker") as pool:
                futures = {pool.submit(self._run_job, dict(job), campaign): job for job in jobs}
                for future in as_completed(futures):
                    job = futures[future]
                    try:
                        result = future.result()
                    except BaseException as exc:
                        self.scheduler.finish(job["id"], "FAIL", str(exc))
                        results.append(
                            WorkerResult(
                                run_id="",
                                job_id=job["id"],
                                role=job["role"],
                                status="FAIL",
                                output={},
                                exit_code=1,
                                session_id="",
                                transcript_path=Path("/dev/null"),
                                last_message_path=Path("/dev/null"),
                                error=str(exc),
                            )
                        )
                        continue
                    self._ensure_run_record(result, job, campaign_id)
                    terminal = "PASS" if result.status == "PASS" else ("BLOCKED" if result.status == "BLOCKED" else "FAIL")
                    self.scheduler.finish(job["id"], terminal, result.error)
                    self._ingest(job, result, campaign)
                    results.append(result)
            wave_summaries.append(
                {
                    "wave": wave_number,
                    "jobs": [
                        {"job_id": item.job_id, "role": item.role, "status": item.status, "run_id": item.run_id}
                        for item in results
                    ],
                }
            )
        self.scheduler.refresh(campaign_id)
        self._update_campaign_terminal_state(campaign_id)
        return {"campaign_id": campaign_id, "waves": wave_summaries, "status": self.status(campaign_id)}

    def _run_job(self, job: dict[str, Any], campaign: dict[str, Any]) -> WorkerResult:
        target = self._target_for_campaign(campaign["id"])
        scope = self._scope_for_campaign(campaign["id"])
        fingerprint = json.loads(self.database.one("SELECT fingerprint_json FROM targets WHERE id=?", (campaign["target_id"],))[0])
        upstream = self._upstream_for_job(job)
        input_data = self._json(job.get("input_json"), {})
        query_parts = list(fingerprint.get("knowledge_query_terms", []))
        query_parts.extend([job.get("role", ""), job.get("lane", "")])
        for key in ("title", "class", "root_cause_family", "research_path"):
            value = input_data.get(key)
            if value:
                query_parts.append(str(value))
        knowledge = self.knowledge.route(
            " ".join(query_parts),
            str(job["role"]),
            self.config.knowledge_top_k,
            campaign_id=campaign["id"],
            max_chars=self.config.max_knowledge_chars_per_doc,
        )
        workspace: Path | None = None
        if job["role"] == "reproducer" and input_data.get("workspace_mode") == "isolated-write":
            if not scope.get("allowed_actions", {}).get("local_tests", False):
                raise ScopeError(["reproducer requested writable workspace but local_tests is not authorized"])
            workspace = self.workspaces.isolated_copy(target, campaign["id"], job["id"])
        return self.runner.run(
            job=job,
            campaign=campaign,
            scope=scope,
            fingerprint=fingerprint,
            target_root=target,
            knowledge=knowledge,
            upstream=upstream,
            workspace=workspace,
        )

    def _ensure_run_record(self, result: WorkerResult, job: dict[str, Any], campaign_id: str) -> None:
        if not result.run_id or self.database.one("SELECT id FROM worker_runs WHERE id=?", (result.run_id,)):
            return
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO worker_runs(
                    id, campaign_id, job_id, role, lane, status, session_id,
                    prompt_sha256, input_json, output_json, output_schema,
                    transcript_path, last_message_path, workspace, exit_code,
                    started_at, completed_at, error
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    result.run_id,
                    campaign_id,
                    job["id"],
                    job["role"],
                    job.get("lane", ""),
                    result.status,
                    result.session_id,
                    "scripted",
                    job.get("input_json", "{}"),
                    canonical_json(result.output),
                    "scripted",
                    str(result.transcript_path),
                    str(result.last_message_path),
                    "scripted",
                    result.exit_code,
                    utcnow(),
                    utcnow(),
                    result.error,
                ),
            )

    def _ingest(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        if result.status != "PASS":
            self.database.event(
                campaign["id"],
                "worker_job",
                job["id"],
                "WORKER_OUTPUT_NOT_INGESTED",
                {"status": result.status, "error": result.error},
            )
            return
        handlers = {
            "mapper": self._ingest_mapper,
            "researcher": self._ingest_researcher,
            "reproducer": self._ingest_reproducer,
            "skeptic": self._ingest_skeptic,
            "prior_art": self._ingest_prior_art,
            "evidence_judge": self._ingest_judge,
        }
        handler = handlers.get(job["role"])
        if handler is None:
            raise ValueError(f"no ingest handler for role {job['role']}")
        handler(job, result, campaign)

    def _ingest_mapper(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        now = utcnow()
        with self.database.transaction(immediate=True) as connection:
            for surface in result.output.get("attack_surfaces", []):
                connection.execute(
                    """
                    INSERT INTO attack_surfaces(
                        campaign_id, surface_key, kind, name, location, trust_boundary,
                        protected_sink, evidence_json, status
                    ) VALUES(?,?,?,?,?,?,?,?,'MAPPED')
                    ON CONFLICT(campaign_id, surface_key) DO UPDATE SET
                        kind=excluded.kind, name=excluded.name, location=excluded.location,
                        trust_boundary=excluded.trust_boundary, protected_sink=excluded.protected_sink,
                        evidence_json=excluded.evidence_json, status='MAPPED'
                    """,
                    (
                        campaign["id"],
                        surface["key"],
                        surface["kind"],
                        surface["name"],
                        surface["location"],
                        surface["trust_boundary"],
                        surface["protected_sink"],
                        canonical_json(surface.get("evidence", [])),
                    ),
                )
            target = connection.execute("SELECT * FROM targets WHERE id=?", (campaign["target_id"],)).fetchone()
            fingerprint = json.loads(target["fingerprint_json"])
            terms = set(fingerprint.get("knowledge_query_terms", []))
            terms.update(result.output.get("knowledge_query_terms", []))
            fingerprint["knowledge_query_terms"] = sorted(terms)
            fingerprint["mapper"] = {
                "architecture": result.output.get("architecture", []),
                "entrypoints": result.output.get("entrypoints", []),
                "trust_boundaries": result.output.get("trust_boundaries", []),
                "protected_sinks": result.output.get("protected_sinks", []),
                "release_reachability": result.output.get("release_reachability", []),
                "unknowns": result.output.get("unknowns", []),
            }
            connection.execute(
                "UPDATE targets SET fingerprint_json=?, updated_at=? WHERE id=?",
                (canonical_json(fingerprint), now, campaign["target_id"]),
            )
        for priority, (lane, assignment) in enumerate(LANES.items(), start=10):
            path_id = new_id("RP")
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO research_paths(
                        id, campaign_id, attack_surface, hypothesis_family, status,
                        status_reason, assigned_roles_json, wave_id, root_cause_family,
                        created_at, updated_at
                    ) VALUES(?,?,?,'target-native','ACTIVE','initial core wave',?,'WAVE-1','',?,?)
                    """,
                    (path_id, campaign["id"], lane, canonical_json([f"researcher:{lane}"]), now, now),
                )
            self.scheduler.create_job(
                campaign["id"],
                "researcher",
                lane=lane,
                priority=priority,
                depends_on=[job["id"]],
                input_data={"assignment": assignment, "research_path_id": path_id, "wave": 1},
                max_attempts=self.config.max_worker_attempts,
            )

    def _ingest_researcher(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        input_data = self._json(job.get("input_json"), {})
        path_id = input_data.get("research_path_id")
        hypotheses = result.output.get("hypotheses", [])
        if not hypotheses:
            self._record_zero_evidence(campaign["id"], path_id, job["lane"], result.output.get("stop_reason", "no hypothesis"))
            return
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE research_paths SET status='PROMISING', status_reason=?, zero_evidence_waves=0, updated_at=? WHERE id=?",
                (f"{len(hypotheses)} hypothesis records", utcnow(), path_id),
            )
        for item in hypotheses:
            existing = None
            root_family = str(item.get("root_cause_family", "")).strip()
            if root_family:
                existing = self.database.one(
                    "SELECT id FROM candidates WHERE campaign_id=? AND root_cause_family=? AND state NOT IN ('KILLED') ORDER BY created_at LIMIT 1",
                    (campaign["id"], root_family),
                )
            if existing:
                self.database.event(
                    campaign["id"],
                    "candidate",
                    existing["id"],
                    "DISCOVERY_CONVERGENCE",
                    {"job_id": job["id"], "root_cause_family": root_family, "local_id": item.get("local_id")},
                )
                continue
            hypothesis_id = new_id("H")
            now = utcnow()
            with self.database.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO hypotheses(
                        id, campaign_id, research_path_id, worker_run_id, title,
                        statement, falsifier, root_cause_family, priority,
                        evidence_json, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        hypothesis_id,
                        campaign["id"],
                        path_id,
                        result.run_id,
                        item["title"],
                        item["statement"],
                        item["falsifier"],
                        root_family,
                        int(item.get("priority", 50)),
                        canonical_json(item.get("evidence", [])),
                        now,
                        now,
                    ),
                )
            candidate_id = self.candidates.create(
                campaign["id"],
                item["title"],
                hypothesis_id=hypothesis_id,
                candidate_class=item.get("class", "unknown"),
                root_cause_family=root_family,
                dossier={"discovery": item, "source_worker_run": result.run_id, "research_path_id": path_id},
            )
            common_input = {
                "candidate_id": candidate_id,
                "title": item["title"],
                "class": item.get("class", "unknown"),
                "root_cause_family": root_family,
                "research_path": item.get("research_path", ""),
                "candidate_dossier": item,
            }
            scope = self._scope_for_campaign(campaign["id"])
            self.scheduler.create_job(
                campaign["id"],
                "reproducer",
                lane=job["lane"],
                priority=20,
                depends_on=[job["id"]],
                input_data={
                    **common_input,
                    "workspace_mode": "isolated-write"
                    if scope.get("allowed_actions", {}).get("local_tests", False)
                    else "read-only",
                },
                max_attempts=self.config.max_worker_attempts,
            )
            self.scheduler.create_job(
                campaign["id"],
                "skeptic",
                lane=job["lane"],
                priority=15,
                depends_on=[job["id"]],
                input_data=common_input,
                max_attempts=self.config.max_worker_attempts,
            )
            if not campaign["novel_discovery_mode"]:
                self.scheduler.create_job(
                    campaign["id"],
                    "prior_art",
                    lane=job["lane"],
                    priority=15,
                    depends_on=[job["id"]],
                    input_data=common_input,
                    max_attempts=self.config.max_worker_attempts,
                )

    def _ingest_reproducer(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        output = result.output
        candidate_id = output["candidate_id"]
        self.candidates.update(
            candidate_id,
            attacker_control=output["attacker_control"],
            reachability=output["reachability"],
            protected_boundary=output["protected_boundary"],
            capability_delta=output["capability_delta"],
            reproduction_attempts=int(output["attempts"]),
            reproduction_successes=int(output["successes"]),
            negative_control=output["negative_control"],
            counterfactual=output["counterfactual"],
        )
        kill = self._reproducer_kill(output)
        if kill:
            self.candidates.kill(candidate_id, kill[0], kill[1], output.get("evidence", []), actor="reproducer")
            return
        self.candidates.advance(candidate_id, actor="reproducer")
        self._maybe_schedule_judge(campaign["id"], candidate_id)

    @staticmethod
    def _reproducer_kill(output: dict[str, Any]) -> tuple[str, str] | None:
        if output["attacker_control"] == "FAILED":
            return "KILL_NO_ATTACKER_CONTROL", "independent reproduction disproved attacker control"
        if output["reachability"] == "UNREACHABLE":
            return "KILL_UNREACHABLE", "independent reproduction proved the path unreachable"
        if output["protected_boundary"] == "FAILED":
            return "KILL_NO_PROTECTED_EFFECT", "no protected boundary was crossed"
        if output["capability_delta"] == "FAILED":
            return "KILL_NO_CAPABILITY_DELTA", "no capability delta beyond starting authority"
        return None

    def _ingest_skeptic(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        output = result.output
        candidate_id = output["candidate_id"]
        verdict = output["verdict"]
        if verdict == "KILL":
            code = output.get("kill_code", "")
            if code not in KILL_CODES:
                code = "KILL_SCHEMA_INVALID"
            self.candidates.kill(candidate_id, code, output.get("kill_reason", "skeptic rejected candidate"), output.get("evidence", []))
            return
        self.candidates.update(candidate_id, skeptic="PASS" if verdict == "PASS" else "BLOCKED")
        self.candidates.advance(candidate_id, actor="skeptic")
        self._maybe_schedule_judge(campaign["id"], candidate_id)

    def _ingest_prior_art(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        output = result.output
        candidate_id = output["candidate_id"]
        with self.database.connect() as connection:
            for source in output.get("sources", []):
                connection.execute(
                    """
                    INSERT INTO prior_art(
                        campaign_id, candidate_id, source_type, title, url, status,
                        root_cause_match, evidence_json, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        campaign["id"],
                        candidate_id,
                        source["type"],
                        source["title"],
                        source["url"],
                        source["status"],
                        source["root_cause_match"],
                        canonical_json({"evidence": source["evidence"]}),
                        utcnow(),
                    ),
                )
        decision = output["decision"]
        if decision in {"KNOWN", "FIXED"}:
            self.candidates.kill(candidate_id, "KILL_KNOWN", output.get("root_cause_overlap", decision), actor="prior-art")
            return
        if decision == "DUPLICATE":
            self.candidates.kill(candidate_id, "KILL_DUPLICATE", output.get("root_cause_overlap", decision), actor="prior-art")
            return
        self.candidates.update(candidate_id, prior_art="CLEAR" if decision == "CLEAR" else "BLOCKED")
        self.candidates.advance(candidate_id, actor="prior-art")
        self._maybe_schedule_judge(campaign["id"], candidate_id)

    def _ingest_judge(self, job: dict[str, Any], result: WorkerResult, campaign: dict[str, Any]) -> None:
        output = result.output
        candidate_id = output["candidate_id"]
        current = self.candidates.get(candidate_id)
        manual_status = current["manual_status"]
        self.candidates.update(
            candidate_id,
            verdict=output["verdict"] if output["verdict"] != "BLOCKED" else current["verdict"],
            evidence_gate=output["evidence_gate"],
            impact_gate=output["impact_gate"],
            manual_status=manual_status,
            severity_status=output["severity_status"],
            severity_locked=int(output["severity_locked"]),
            triager_proof=output["triager_proof"],
        )
        self.candidates.advance(candidate_id, actor="evidence-judge")

    def _maybe_schedule_judge(self, campaign_id: str, candidate_id: str) -> None:
        candidate = self.candidates.get(candidate_id)
        if candidate["state"] in {"KILLED", "BLOCKED", "REPORT_READY"}:
            return
        jobs = self.database.all(
            "SELECT role, status, input_json FROM worker_jobs WHERE campaign_id=? AND role IN ('reproducer','skeptic','prior_art','evidence_judge')",
            (campaign_id,),
        )
        related = []
        judge_exists = False
        for job in jobs:
            data = self._json(job["input_json"], {})
            if data.get("candidate_id") != candidate_id:
                continue
            if job["role"] == "evidence_judge":
                judge_exists = True
            else:
                related.append(job)
        required_roles = {"reproducer", "skeptic"}
        campaign = self._campaign(campaign_id)
        if not campaign["novel_discovery_mode"]:
            required_roles.add("prior_art")
        complete_roles = {job["role"] for job in related if job["status"] == "PASS"}
        if judge_exists or not required_roles.issubset(complete_roles):
            return
        if campaign["novel_discovery_mode"] and candidate["prior_art"] == "NOT_CHECKED":
            self.scheduler.create_job(
                campaign_id,
                "prior_art",
                lane="post-proof",
                priority=5,
                input_data={
                    "candidate_id": candidate_id,
                    "title": candidate["title"],
                    "class": candidate["class"],
                    "root_cause_family": candidate["root_cause_family"],
                    "candidate_dossier": self._json(candidate["dossier_json"], {}),
                },
                max_attempts=self.config.max_worker_attempts,
            )
            return
        if candidate["prior_art"] != "CLEAR":
            return
        dependency_ids = []
        for job in self.database.all(
            "SELECT id, input_json FROM worker_jobs WHERE campaign_id=? AND role IN ('reproducer','skeptic','prior_art')",
            (campaign_id,),
        ):
            if self._json(job["input_json"], {}).get("candidate_id") == candidate_id:
                dependency_ids.append(job["id"])
        self.scheduler.create_job(
            campaign_id,
            "evidence_judge",
            lane="judgment",
            priority=1,
            depends_on=dependency_ids,
            input_data={
                "candidate_id": candidate_id,
                "title": candidate["title"],
                "class": candidate["class"],
                "root_cause_family": candidate["root_cause_family"],
                "candidate_bundle": self._candidate_bundle(candidate_id),
                "current_state": candidate["state"],
                "manual_status": candidate["manual_status"],
            },
            max_attempts=self.config.max_worker_attempts,
        )

    def _record_zero_evidence(self, campaign_id: str, path_id: str | None, lane: str, reason: str) -> None:
        if not path_id:
            return
        with self.database.transaction(immediate=True) as connection:
            path = connection.execute("SELECT * FROM research_paths WHERE id=?", (path_id,)).fetchone()
            if not path:
                return
            waves = int(path["zero_evidence_waves"]) + 1
            terminal = waves >= 2
            status = "EXHAUSTED" if terminal else "ACTIVE"
            connection.execute(
                "UPDATE research_paths SET zero_evidence_waves=?, status=?, status_reason=?, updated_at=? WHERE id=?",
                (waves, status, reason, utcnow(), path_id),
            )
            if terminal:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO burned_paths(
                        campaign_id, path_key, reason, kill_code, evidence_json, reopen_condition, created_at
                    ) VALUES(?,?,?,'KILL_NO_MATERIAL_EVIDENCE','[]',?,?)
                    """,
                    (
                        campaign_id,
                        f"lane:{lane}",
                        reason,
                        "materially new trust-boundary, consumer, runtime, or release evidence",
                        utcnow(),
                    ),
                )

    def _upstream_for_job(self, job: dict[str, Any]) -> list[dict[str, Any]]:
        dependencies = self._json(job.get("depends_on_json"), [])
        if not dependencies:
            return []
        placeholders = ",".join("?" for _ in dependencies)
        rows = self.database.all(
            f"""
            SELECT wr.id, wr.job_id, wr.role, wr.status, wr.output_json
            FROM worker_runs wr
            WHERE wr.job_id IN ({placeholders})
            ORDER BY wr.started_at
            """,
            dependencies,
        )
        return [
            {
                "run_id": row["id"],
                "job_id": row["job_id"],
                "role": row["role"],
                "status": row["status"],
                "output": self._json(row["output_json"], {}),
            }
            for row in rows
        ]

    def focus(self, campaign_id: str, lane: str, question: str) -> str:
        campaign = self._campaign(campaign_id)
        if campaign["status"] not in {"ACTIVE", "BLOCKED"}:
            raise ValueError(f"campaign is not active: {campaign['status']}")
        path_id = new_id("RP")
        now = utcnow()
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO research_paths(
                    id, campaign_id, attack_surface, hypothesis_family, status,
                    status_reason, assigned_roles_json, wave_id, root_cause_family,
                    created_at, updated_at
                ) VALUES(?,?,?,'adaptive','ACTIVE',?,'["researcher"]','ADAPTIVE','',?,?)
                """,
                (path_id, campaign_id, lane, question, now, now),
            )
        return self.scheduler.create_job(
            campaign_id,
            "researcher",
            lane=lane,
            priority=5,
            input_data={"assignment": question, "research_path_id": path_id, "wave": "adaptive"},
            max_attempts=self.config.max_worker_attempts,
        )

    def stop_lane(self, campaign_id: str, lane: str, reason: str) -> int:
        count = self.scheduler.cancel_lane(campaign_id, lane, reason)
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE research_paths SET status='STOPPED', status_reason=?, updated_at=? WHERE campaign_id=? AND attack_surface=? AND status IN ('ACTIVE','PROMISING','BLOCKED')",
                (reason, utcnow(), campaign_id, lane),
            )
        return count

    def abort_campaign(self, campaign_id: str, reason: str) -> dict[str, Any]:
        """Stop queued work and close a campaign while retaining its audit trail."""
        now = utcnow()
        with self.database.transaction(immediate=True) as connection:
            campaign = connection.execute(
                "SELECT status FROM campaigns WHERE id=?",
                (campaign_id,),
            ).fetchone()
            if not campaign:
                raise KeyError(campaign_id)
            running = connection.execute(
                "SELECT count(*) FROM worker_jobs WHERE campaign_id=? AND status='RUNNING'",
                (campaign_id,),
            ).fetchone()[0]
            if running:
                raise RuntimeError(
                    f"campaign has {running} running worker(s); interrupt those processes before aborting"
                )
            queued = connection.execute(
                "SELECT id FROM worker_jobs WHERE campaign_id=? AND status IN ('PENDING','READY')",
                (campaign_id,),
            ).fetchall()
            connection.execute(
                """
                UPDATE worker_jobs
                SET status='CANCELLED', last_error=?, updated_at=?
                WHERE campaign_id=? AND status IN ('PENDING','READY')
                """,
                (reason, now, campaign_id),
            )
            connection.execute(
                """
                UPDATE research_paths
                SET status='STOPPED', status_reason=?, updated_at=?
                WHERE campaign_id=? AND status IN ('ACTIVE','PROMISING','BLOCKED')
                """,
                (reason, now, campaign_id),
            )
            connection.execute(
                "UPDATE campaigns SET status='ABORTED', completed_at=?, updated_at=? WHERE id=?",
                (now, now, campaign_id),
            )
            for job in queued:
                self.database.event(
                    campaign_id,
                    "worker_job",
                    job["id"],
                    "JOB_CANCELLED",
                    {"reason": reason},
                    connection,
                )
            self.database.event(
                campaign_id,
                "campaign",
                campaign_id,
                "CAMPAIGN_ABORTED",
                {"reason": reason, "jobs_cancelled": len(queued)},
                connection,
            )
        return {"campaign_id": campaign_id, "status": "ABORTED", "jobs_cancelled": len(queued)}

    def manual_confirm(
        self,
        candidate_id: str,
        attempts: int,
        successes: int,
        evidence_uris: list[str],
        cleanup: str,
    ) -> dict[str, Any]:
        if attempts < 3 or successes != attempts:
            raise ValueError("manual confirmation requires at least 3 successful attempts with no failed attempt")
        if not evidence_uris:
            raise ValueError("manual confirmation requires at least one evidence URI")
        row = self.candidates.get(candidate_id)
        stored_evidence: list[dict[str, str | int]] = []
        evidence_store = EvidenceStore(self.database, self.paths)
        for raw_path in evidence_uris:
            evidence_path = Path(raw_path).expanduser().resolve()
            if not evidence_path.is_file():
                raise FileNotFoundError(evidence_path)
            stored_evidence.append(
                evidence_store.add_file(
                    row["campaign_id"],
                    evidence_path,
                    "manual-reproduction",
                    candidate_id=candidate_id,
                    summary="researcher manual reproduction evidence",
                )
            )
        self.candidates.update(
            candidate_id,
            reproduction_attempts=attempts,
            reproduction_successes=successes,
            manual_status="MANUALLY_CONFIRMED",
        )
        row = self.candidates.get(candidate_id)
        self.database.event(
            row["campaign_id"],
            "candidate",
            candidate_id,
            "MANUAL_REPRODUCTION_CONFIRMED",
            {"attempts": attempts, "successes": successes, "evidence": stored_evidence, "cleanup": cleanup},
        )
        transition = self.candidates.advance(candidate_id, actor="human-researcher")
        current = self.candidates.get(candidate_id)
        judge_job = self.scheduler.create_job(
            row["campaign_id"],
            "evidence_judge",
            lane="post-manual-judgment",
            priority=0,
            input_data={
                "candidate_id": candidate_id,
                "title": current["title"],
                "class": current["class"],
                "root_cause_family": current["root_cause_family"],
                "candidate_bundle": self._candidate_bundle(candidate_id),
                "current_state": current["state"],
                "manual_status": "MANUALLY_CONFIRMED",
                "manual_evidence": stored_evidence,
                "cleanup": cleanup,
            },
            max_attempts=self.config.max_worker_attempts,
        )
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE campaigns SET status='ACTIVE', completed_at=NULL, updated_at=? WHERE id=?",
                (utcnow(), row["campaign_id"]),
            )
        return {**transition, "judge_job": judge_job, "evidence": stored_evidence}

    def _candidate_bundle(self, candidate_id: str) -> dict[str, Any]:
        candidate = self.candidates.get(candidate_id)
        reviews: list[dict[str, Any]] = []
        for row in self.database.all(
            """
            SELECT wr.id, wr.role, wr.status, wr.output_json, wj.input_json
            FROM worker_runs wr JOIN worker_jobs wj ON wj.id=wr.job_id
            WHERE wr.campaign_id=? AND wr.role IN ('reproducer','skeptic','prior_art','evidence_judge')
            ORDER BY wr.started_at
            """,
            (candidate["campaign_id"],),
        ):
            job_input = self._json(row["input_json"], {})
            if job_input.get("candidate_id") != candidate_id:
                continue
            reviews.append(
                {
                    "run_id": row["id"],
                    "role": row["role"],
                    "status": row["status"],
                    "output": self._json(row["output_json"], {}),
                }
            )
        evidence = [
            {
                "id": row["id"],
                "kind": row["kind"],
                "uri": row["uri"],
                "sha256": row["sha256"],
                "summary": row["summary"],
            }
            for row in self.database.all(
                "SELECT id, kind, uri, sha256, summary FROM evidence WHERE candidate_id=? ORDER BY created_at",
                (candidate_id,),
            )
        ]
        transitions = [
            dict(row)
            for row in self.database.all(
                "SELECT from_state, to_state, reason, actor, created_at FROM candidate_transitions WHERE candidate_id=? ORDER BY id",
                (candidate_id,),
            )
        ]
        return {
            "candidate": {
                key: candidate[key]
                for key in (
                    "id",
                    "title",
                    "class",
                    "root_cause_family",
                    "state",
                    "attacker_control",
                    "reachability",
                    "protected_boundary",
                    "capability_delta",
                    "reproduction_attempts",
                    "reproduction_successes",
                    "negative_control",
                    "counterfactual",
                    "skeptic",
                    "prior_art",
                    "evidence_gate",
                    "impact_gate",
                    "manual_status",
                    "severity_status",
                    "severity_locked",
                    "triager_proof",
                )
            },
            "reviews": reviews,
            "evidence": evidence,
            "transitions": transitions,
        }

    def status(self, campaign_id: str) -> dict[str, Any]:
        campaign = dict(self._campaign(campaign_id))
        target = dict(self.database.one("SELECT * FROM targets WHERE id=?", (campaign["target_id"],)))
        candidates = [
            {
                "id": row["id"],
                "title": row["title"],
                "state": row["state"],
                "verdict": row["verdict"],
                "kill_code": row["kill_code"],
                "report_ready": bool(row["report_ready"]),
            }
            for row in self.database.all(
                "SELECT * FROM candidates WHERE campaign_id=? ORDER BY created_at", (campaign_id,)
            )
        ]
        path_counts = {
            row["status"]: int(row["count"])
            for row in self.database.all(
                "SELECT status, count(*) AS count FROM research_paths WHERE campaign_id=? GROUP BY status",
                (campaign_id,),
            )
        }
        return {
            "campaign": {
                "id": campaign["id"],
                "status": campaign["status"],
                "objective": campaign["objective"],
                "scope_status": campaign["scope_status"],
                "created_at": campaign["created_at"],
                "updated_at": campaign["updated_at"],
            },
            "target": {
                "root": target["root_path"],
                "commit": target["repo_commit"],
                "branch": target["branch"],
                "dirty": bool(target["dirty"]),
            },
            "jobs": self.scheduler.counts(campaign_id),
            "research_paths": path_counts,
            "candidates": candidates,
            "counts": {
                "attack_surfaces": int(self.database.one("SELECT count(*) FROM attack_surfaces WHERE campaign_id=?", (campaign_id,))[0]),
                "hypotheses": int(self.database.one("SELECT count(*) FROM hypotheses WHERE campaign_id=?", (campaign_id,))[0]),
                "candidates": len(candidates),
                "report_ready": sum(1 for item in candidates if item["report_ready"]),
            },
        }

    def current_campaign(self, target: Path) -> str:
        marker = target.expanduser().resolve() / ".bbpresearch" / "campaign.json"
        if not marker.exists():
            raise KeyError(f"no active campaign marker at {marker}")
        return str(json.loads(marker.read_text(encoding="utf-8"))["active_campaign_id"])

    def _update_campaign_terminal_state(self, campaign_id: str) -> None:
        counts = self.scheduler.counts(campaign_id)
        active = sum(counts.get(name, 0) for name in ("PENDING", "READY", "RUNNING"))
        if active:
            return
        blocked_jobs = counts.get("BLOCKED", 0) + counts.get("FAIL", 0)
        unresolved = int(
            self.database.one(
                "SELECT count(*) FROM candidates WHERE campaign_id=? AND state NOT IN ('KILLED','REPORT_READY')",
                (campaign_id,),
            )[0]
        )
        status = "BLOCKED" if blocked_jobs or unresolved else "COMPLETE"
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE campaigns SET status=?, completed_at=?, updated_at=? WHERE id=?",
                (status, utcnow() if status == "COMPLETE" else None, utcnow(), campaign_id),
            )

    def _campaign(self, campaign_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM campaigns WHERE id=?", (campaign_id,))
        if row is None:
            raise KeyError(f"unknown campaign: {campaign_id}")
        return dict(row)

    def _target_for_campaign(self, campaign_id: str) -> Path:
        row = self.database.one(
            "SELECT t.root_path FROM targets t JOIN campaigns c ON c.target_id=t.id WHERE c.id=?",
            (campaign_id,),
        )
        if row is None:
            raise KeyError(campaign_id)
        return Path(row["root_path"])

    def _scope_for_campaign(self, campaign_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT raw_json FROM scope WHERE campaign_id=? ORDER BY id DESC LIMIT 1", (campaign_id,))
        if row is None:
            raise ScopeError([f"campaign {campaign_id} has no scope record"])
        return json.loads(row["raw_json"])

    @staticmethod
    def _json(value: Any, fallback: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return fallback
        return value if value is not None else fallback
