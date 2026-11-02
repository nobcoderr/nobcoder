# Roadmap 10 — First Real Security Worker V35

This public snapshot contains the immutable V35 engineering workspace and its
authorizing V34-to-V35 governance package.

V35 stopped fail-closed during unit validation:

- unit: 408/412 PASS;
- primary and independent validation: not started;
- static lock: not issued;
- attempt, worker, and Codex-as-worker invocation: 0/1;
- terminal state: `FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE`.

The portable ZIP is under `packages/`. Verify it from that directory with:

```sh
sha256sum -c first-real-security-worker-v35-frozen-20261103.zip.sha256
```

Expected ZIP SHA-256:

`d251a5b06ccd9db275b16c8eee05e36f3341cd83d515b4d06a850e1fb7483791`

The frozen V35 evidence root is:

`2f27a2c34dc6ae02401deff932053c7a2c144f71bc5545bb13a37bfbbfc57790`
