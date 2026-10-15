# Codex Security Harness

This Git repository is the harness product. Codex remains the user interface
and a replaceable external runtime dependency behind one deny-by-default
adapter. The repository provides the persistent control plane: scope gating,
SQLite research memory, knowledge retrieval, candidate state transitions,
evidence hashing, resume, and evaluation metrics.

Current repository status is architecture and fixture validation only. The
installed Codex CLI is recorded as a candidate runtime, not an authoritative or
executable runtime. Repository creation grants no campaign, worker, subagent,
target, network, parallel, capability-graph, or submission authority.

See [ARCHITECTURE.md](ARCHITECTURE.md),
[`toolchain/codex.lock.json`](toolchain/codex.lock.json), and the
[compatibility contract](toolchain/compatibility/contract-v1.json).

The intended future workflow, after separate runtime and campaign authorization,
is:

```text
cd ~/bbp/<target>
codex
> mulai autonomous audit
```

The installed `codex-security-harness` skill may translate a separately
authorized request into deterministic `bbp-harness` operations. Future workers
use the `CodexCliRuntime` adapter; core modules do not construct or invoke Codex
commands directly. The master session owns scheduling and every final decision.

## Install

```bash
./scripts/install.sh
```

Restart Codex after installation so the new skill is discovered.

The installer discovers the shared skill pack and the public report corpora in
their standard locations, then builds a local FTS knowledge index. The report
databases remain separate from campaign state: `~/.bbp-ai/state/research.db`
contains the index, research graph, evidence metadata, and resumable jobs.

## Future first campaign (not currently authorized)

```bash
cd ~/bbp/<target>
bbp-harness init
# Record the exact official program boundaries in .bbpresearch/scope.yaml.
bbp-harness scope-check
bbp-harness audit --max-waves 4
```

After an explicit campaign-execution authorization, the equivalent instruction
inside a newly restarted Codex TUI is `mulai autonomous audit`. Operational
controls are `status`, `focus`, `stop-lane`, `pause`, `resume`, `abort`, and
`explain <candidate-id>`. Do not use these commands as authority to run a
campaign before that gate exists.

## Safety model

- User-supplied official program targets use standing authorization, while
  missing or contradictory scope evidence still blocks execution.
- The harness does not ask for repeated authorization at campaign start,
  between workers, before permitted safe probes, or after session restarts.
- Network and state-changing tests are disabled by default.
- Target repositories are read-only for discovery workers.
- Writable reproduction uses an isolated disposable worktree.
- Model output is a hypothesis or review record, never proof by consensus.
- Candidate promotion is performed by a deterministic state machine.
- `REPORT_READY` requires manual confirmation and the triager-proof gate.
- Codex runtime identity, compatibility acceptance, and campaign execution are
  independent gates; all default to denied.
- Updates are candidate runtimes until exact bytes, configuration, compatibility
  invariants, evidence, and governance are independently accepted.

## Developer verification

```bash
python -m unittest discover -s tests -v
```
