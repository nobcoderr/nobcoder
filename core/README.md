# Core

Runtime-independent policy and state-machine logic lives in
`src/bbp_harness`. Core code depends on the `WorkerRuntime` protocol, never on a
Codex command line or version-specific flag.
