#!/usr/bin/env bash
set -euo pipefail

HARNESS_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${HARNESS_PROJECT_ROOT}"
python3 -m compileall -q src tests
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests -t . -v
python3 "${HOME}/.codex/skills/.system/skill-creator/scripts/quick_validate.py" "${HARNESS_PROJECT_ROOT}/skill/codex-security-harness"
