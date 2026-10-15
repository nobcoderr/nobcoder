#!/usr/bin/env bash
set -euo pipefail

HARNESS_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_STATE_HOME="${BBP_AI_HOME:-${HOME}/.bbp-ai}"
HARNESS_BIN_DIR="${HOME}/.local/bin"
HARNESS_BIN_LINK="${HARNESS_BIN_DIR}/bbp-harness"
HARNESS_EXEC="${HARNESS_PROJECT_ROOT}/scripts/bbp-harness"
HARNESS_SKILL_DIR="${HOME}/.codex/skills/codex-security-harness"
HARNESS_SKILL_SOURCE="${HARNESS_PROJECT_ROOT}/skill/codex-security-harness"

mkdir -p "${HARNESS_BIN_DIR}" "${HOME}/.codex/skills"

if [[ -e "${HARNESS_BIN_LINK}" && ! -L "${HARNESS_BIN_LINK}" ]]; then
  echo "Refusing to replace non-symlink: ${HARNESS_BIN_LINK}" >&2
  exit 1
fi
ln -sfn "${HARNESS_EXEC}" "${HARNESS_BIN_LINK}"

if [[ -e "${HARNESS_SKILL_DIR}" && ! -L "${HARNESS_SKILL_DIR}" ]]; then
  echo "Refusing to replace existing skill directory: ${HARNESS_SKILL_DIR}" >&2
  exit 1
fi
ln -sfn "${HARNESS_SKILL_SOURCE}" "${HARNESS_SKILL_DIR}"

"${HARNESS_BIN_LINK}" db

if [[ "${1:-}" != "--skip-index" ]]; then
  "${HARNESS_BIN_LINK}" index
fi

"${HARNESS_BIN_LINK}" doctor
echo "Installed. Restart Codex so the codex-security-harness skill is discovered."
