# Contributing to Codex Security Harness

Thank you for considering a contribution. The project is at an early
development stage and prioritizes deterministic, reproducible controls.

## Scope of contributions

Useful contributions include documentation clarifications, local fixtures,
unit tests, code review, packaging fixes, and well-scoped maintenance changes.

Before proposing a change, read [AGENTS.md](AGENTS.md),
[ARCHITECTURE.md](ARCHITECTURE.md), and the [README](README.md).

## Local development

- Python 3.11 or newer is required.
- Runtime dependencies are currently limited to the Python standard library.
- Codex CLI is an optional, external, version-pinned runtime candidate.
- **Do not invoke Codex CLI or external targets from unit tests.**

Run the local tests:

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests -t . -v
```

## Pull requests

1. Open an issue or explain the purpose and risk in the pull request.
2. Keep changes narrow, document behavior changes, and add fixture-based tests.
3. Explain how you validated the change and what remains untested.
4. Avoid submitting credentials, sensitive reports, live target data, or private evidence.
5. Preserve frozen evidence, digest-bound manifests, authorization records, and
   deny-by-default behavior. Do not modify or reauthorize them as part of routine work.
6. Do not enable live network probes, worker execution, or security campaigns.
   Such operations require a separate explicit authorization process.

Maintainers review and merge changes at their discretion. Passing tests or
model-generated reviews do not constitute permission to execute a campaign.

## Licensing and external contributions

By submitting a contribution you confirm that you have the right to submit
it under the project's [Apache-2.0 license](LICENSE), unless explicitly
agreed otherwise. Do not copy upstream code or data without preserving its
license, attribution, and applicable distribution conditions.

Historical archives and external corpora have separate licensing considerations:
see [THIRD_PARTY.md](THIRD_PARTY.md).

## Reporting security issues

Please do not post exploit details, credentials, or sensitive evidence in
public issues. Contact the maintainers through a private channel where available;
use GitHub's private vulnerability reporting feature if it is enabled for
this repository.
