#!/usr/bin/env bash
# agent-shield — 30-second live demo of the Layer 4 bash_guard.
#
# Runs the REAL PreToolUse guard against three commands so you can watch it:
#   * block a destructive command  (deny)
#   * prompt on a risky one         (ask)
#   * allow a safe one              (allow — silent, exit 0)
#
# Usage:    bash demo/demo.sh
# Requires: agent-shield installed (`pip install git+https://github.com/esoteric1entity/agent-shield.git`,
#           or, from a repo checkout, `pip install -e .`). Pure Python; no other dependencies.
# Override the interpreter with the PYTHON env var if needed.
#
# Recording the GIF / asciinema for the README: see demo/README.md.

set -u

# --- resolve a Python interpreter -------------------------------------------
PY="${PYTHON:-}"
if [ -z "${PY}" ]; then
  if   command -v python3 >/dev/null 2>&1; then PY="python3"
  elif command -v python  >/dev/null 2>&1; then PY="python"
  else
    echo "error: no python3/python found on PATH." >&2
    exit 1
  fi
fi

if ! "${PY}" -c "import agent_shield" >/dev/null 2>&1; then
  echo "error: agent-shield is not importable under '${PY}'." >&2
  echo "       install it first:  ${PY} -m pip install git+https://github.com/esoteric1entity/agent-shield.git" >&2
  exit 1
fi

# --- colors (skipped when stdout is not a TTY, e.g. piped to a file) --------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=""; DIM=""; GRN=""; CYN=""; RST=""
fi

# Feed one command through the real guard and print the decision it returns.
demo_case() {
  local cmd="$1" json out
  json="{\"tool_input\":{\"command\":\"${cmd}\"}}"
  printf '\n%s$%s echo %s | python -m agent_shield.bash_guard\n' "${GRN}" "${RST}" "'${json}'"
  out="$(printf '%s' "${json}" | "${PY}" -m agent_shield.bash_guard)"
  if [ -z "${out}" ]; then
    printf '  %s(no output — allowed, exit 0)%s\n' "${DIM}" "${RST}"
  else
    printf '  %s\n' "${out}"
  fi
}

printf '%s%sagent-shield · Layer 4 · bash_guard%s %s(PreToolUse hook)%s\n' \
  "${BOLD}" "${CYN}" "${RST}" "${DIM}" "${RST}"

demo_case "rm -rf /"
demo_case "git push --force origin main"
demo_case "ls -la"

printf '\n%sSilence = allow. Only ask / deny emit JSON.%s\n' "${DIM}" "${RST}"
