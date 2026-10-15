# Harness architecture

The Git repository is the product. Codex CLI is an external, versioned runtime
dependency behind one adapter boundary.

```text
contracts + core + campaign state
                 |
                 v
          WorkerRuntime
                 |
                 v
   adapters/codex_cli (deny by default)
                 |
                 v
       pinned Codex CLI candidate
```

The implementation package remains under `src/bbp_harness`. The top-level
directories define architectural ownership and stable contract locations:

- `core/`: runtime-independent state and policy;
- `contracts/`: normative schemas and frozen contracts;
- `campaign/`: campaign orchestration contracts;
- `adapters/codex_cli/`: documentation for the only Codex CLI boundary;
- `toolchain/`: runtime identity and compatibility records;
- `fixtures/`: inert compatibility inputs;
- `evidence/`: indexes and manifests only; sensitive/local payloads are ignored;
- `governance/`: append-only decisions and status records;
- `tests/`: pure local fixtures with no model or target calls.

Historical locked evidence remains in its original immutable locations. This
repository may contain digest-bound references to it, but repository creation
does not copy, reinterpret, or promote those artifacts.

## Authority boundary

Source presence is not execution authority. A Codex runtime may be invoked only
when all of the following are independently true:

1. its byte identity matches `toolchain/codex.lock.json`;
2. compatibility state is `PASS_LOCKED`;
3. the runtime lock explicitly permits invocation;
4. the local harness configuration explicitly permits invocation;
5. the requested campaign operation has its own separate authorization.

The initial lock intentionally fails conditions 2–4. It records the installed
candidate without authorizing it.
