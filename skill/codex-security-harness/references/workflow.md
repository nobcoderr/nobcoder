# Harness operating workflow

## Control plane

`~/.bbp-ai/state/research.db` is authoritative. Chat is a cockpit, not the
database. Evidence is copied into a SHA-256-addressed store under
`~/.bbp-ai/evidence`; worker prompts, transcripts, outputs, job leases,
transitions, burned paths, and prior art remain queryable after a crash.

## Starting a campaign

1. Run `bbp-harness init --target "$PWD"` if `.bbpresearch` is absent.
2. When the target came from an official program scope supplied by the user,
   retain the generated standing-authorization fields and encode the exact
   program boundaries in the remaining scope card. Do not request a redundant
   authorization confirmation at startup, between workers, before a permitted
   safe probe, or after a session restart. This authorization persists until
   revoked, the target changes, or scope evidence becomes missing or
   contradictory; only then stop at `BLOCKED_SCOPE`.
3. Run `bbp-harness scope-check --target "$PWD"`.
4. Only after PASS, run `bbp-harness audit --target "$PWD" --objective '<objective>'`.
5. Summarize the returned campaign ID, revision, scope result, active workers,
   hypotheses, candidates, and blocked gates. Do not paste full worker output.

The first wave is mapper -> authority, representation, and state/composition
researchers. Candidate-specific reproducer, skeptic, and prior-art jobs then run
in isolated contexts. A fresh evidence judge receives structured evidence, not
discovery rhetoric.

## Candidate state machine

```text
HYPOTHESIS
  -> CANDIDATE
  -> REPRODUCED
  -> NEGATIVE_CONTROL_PASS
  -> COUNTERFACTUAL_PASS
  -> SKEPTIC_PASS
  -> PRIOR_ART_CLEAR
  -> STRONG
  -> REPORT_READY
```

Any non-terminal stage may end in a specific KILL or BLOCKED state. Use
`bbp-harness explain C-...` to answer “why was this killed?” from stored gates
and transition history.

`STRONG` requires `MANUALLY_CONFIRMED`; never record that status based on model
output. After the researcher performs the allowed harmless reproduction, record
it with `bbp-harness manual-confirm` and the exact immutable evidence URIs.

## Steering

- “status” -> query status; do not start more workers.
- “focus on X” -> create one bounded adaptive lane with a falsifiable question.
- “stop X lane” -> cancel only queued work for that lane and preserve history.
- “continue” -> resume stale leases and execute only dependency-ready jobs.
- “continue until exhausted” -> keep the configured wave/budget limits; two
  zero-material-evidence waves exhaust a path.

Writable local reproduction uses a disposable managed copy under
`~/.bbp-ai/workspaces`. Discovery workers remain read-only. Public web research
is only for prior art and does not authorize requests to the target.

## Knowledge routing

The harness indexes skills, agents, prompts, methodologies, patterns, and public
report metadata into FTS5. Each worker receives only top-K target-native
matches. Historical reports are prior-art and negative-control material, never
proof that the current target is vulnerable.

## Completion

Stop when all material paths are terminal, only repeated root causes remain,
budget/scope/safety blocks progress, or survivors have moved to human
reproduction. `NO VALID FINDING` is a valid completed result. Preserve exact
unblock conditions instead of recycling dead lanes.
