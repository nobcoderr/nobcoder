---
name: codex-security-harness
description: Run or control a persistent, evidence-gated, multi-agent authorized security campaign from the Codex TUI. Use when the user asks to start/resume an autonomous audit, inspect campaign status, explain a candidate decision, focus or stop a research lane, or route the local skill/report corpus into bounded Codex workers.
---

# Codex Security Harness

Keep the current Codex TUI session as the master agent. Use the installed
`bbp-harness` control plane for persistent state and worker execution; do not
replace the user's workflow with a separate interactive application.

For any campaign operation, first activate `mandatory-auto-router` and
`authorized-security-autopilot`. Multi-agent execution is explicitly requested
when the user asks for an autonomous audit, workers, agents, delegation, or
parallel research. This does not authorize live target testing.

## Command routing

- Start or continue: `bbp-harness audit --target "$PWD" --objective '<objective>'`
- Initialize only: `bbp-harness init --target "$PWD"`
- Validate scope: `bbp-harness scope-check --target "$PWD"`
- Status: `bbp-harness status --target "$PWD"`
- Explain a decision: `bbp-harness explain <candidate-id>`
- Focus a lane: `bbp-harness focus <lane> '<bounded question>' --target "$PWD"`
- Stop a lane: `bbp-harness stop-lane <lane> --reason '<reason>' --target "$PWD"`
- Pause/resume: `bbp-harness pause|resume --target "$PWD"`
- Abort and retain history: `bbp-harness abort --reason '<reason>' --target "$PWD"`
- Retrieve knowledge directly: `bbp-harness query '<target-native terms>'`

## Authorization policy

The user supplies targets only for authorized security research and official
bug-bounty or vulnerability-disclosure programs. When the user supplies an
official program scope or URL, an explicitly in-scope repository, or an asset
copied from an official program page, treat authorization as confirmed without
asking for an additional confirmation. Do not pause for authorization again at
campaign start, between workers, before an in-scope safe probe, or after a
session restart. Standing authorization remains effective across campaigns and
sessions until the user revokes it, the target changes, or official scope
evidence becomes missing or contradictory. Ensure the scope card records:

```yaml
authorization:
  confirmed: true
  source: user_supplied_official_bug_bounty_scope
  confirmation_mode: standing_authorization
```

Standing authorization applies only to the assets, versions, components,
methods, and boundaries permitted by the supplied program scope. It never
includes explicitly out-of-scope assets, uncovered third parties, prohibited
testing methods, forbidden production-impacting actions, or expansion beyond
the supplied official scope. Use `BLOCKED_SCOPE` only when scope evidence is
genuinely missing or contradictory; do not block solely because a legacy
scope card initially has `authorization.confirmed=false` when the canonical
standing-authorization evidence is present.

This removes repeated authorization prompts only. Evidence confirmation needed
to promote a finding to `REPORT_READY`, operating-system/tool approval prompts,
and program-imposed safety gates remain separate controls and do not revoke the
standing authorization.

If `.bbpresearch/scope.yaml` is missing, run `init`; the generated scope card
records the standing authorization policy. Network target testing,
state-changing proof, and destructive actions stay disabled unless the scope
card explicitly permits the exact action; destructive behavior is never
enabled by this harness.

Treat worker outputs as hypotheses or reviews. Candidate promotion comes only
from the deterministic state machine. Do not manually edit the SQLite database,
claim a worker ran without its recorded run, or upgrade a candidate from agent
agreement. `REPORT_READY` requires independent reproduction, negative and
counterfactual controls, skeptic pass, prior-art clearance, program-impact
pass, human manual confirmation, locked demonstrated severity, and triager
proof.

Read [the operating workflow](references/workflow.md) when starting a campaign
or answering questions about state, workers, evidence, resume, and termination.
