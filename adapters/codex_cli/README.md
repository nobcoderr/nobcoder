# Codex CLI adapter

The canonical implementation is
`src/bbp_harness/adapters/codex_cli/runtime.py`. This is the only code allowed
to construct Codex-specific argv, verify the pinned runtime identity, or invoke
the Codex process.

The adapter is deny-by-default. It does not infer authority from an installed
binary, a matching hash, a Git repository, a model response, or a compatibility
test. Runtime and campaign authorization are separate gates.
