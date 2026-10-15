# Codex Security Harness development instructions

- Preserve Codex TUI as the primary interface; helper commands are a control plane.
- Treat Codex CLI as an external pinned dependency. Only
  `src/bbp_harness/adapters/codex_cli/` may construct Codex-specific argv,
  inspect its runtime identity, or invoke its process.
- Never infer runtime or campaign authority from repository presence, a matching
  digest, an installed binary, or a passing unit fixture.
- Keep runtime dependencies in the Python standard library unless unavoidable.
- Never execute live security testing from unit tests.
- Use fake/scripted worker outputs in tests; do not spend model calls in CI.
- Keep discovery output separate from deterministic promotion and final judgment.
- Do not weaken scope, evidence, negative-control, prior-art, manual-confirmation,
  or triager-proof gates.
- Preserve user repositories: discovery is read-only and writable tests use
  isolated workspaces.
