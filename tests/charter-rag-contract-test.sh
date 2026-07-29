#!/usr/bin/env bash
# Contract test for the hermetic Charter corpus runner. This suite deliberately
# runs from outside the repository and shadows live-service tools, so a passing
# result proves the runner stays on the committed offline unittest path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$REPO_ROOT/tests/run-charter-rag-contract.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
sect() { printf '\n== %s ==\n' "$1"; }

require() {
  if "$@"; then
    ok "$2"
  else
    bad "$2"
  fi
}

[ -x "$RUNNER" ] || { echo "missing executable runner: $RUNNER" >&2; exit 2; }

FAKE_BIN="$WORK/fake-bin"
mkdir -p "$FAKE_BIN" "$WORK/non-repo-cwd" "$WORK/copied-root/tests"
for command in docker curl wget; do
  printf '#!/usr/bin/env bash\nprintf "unexpected %s invocation\\n" "$0" >&2\nexit 97\n' "$command" > "$FAKE_BIN/$command"
  chmod +x "$FAKE_BIN/$command"
done

sect "runner executes the eight-case corpus contract from outside the repository"
output="$WORK/runner-output.txt"
if (
  cd "$WORK/non-repo-cwd"
  PATH="$FAKE_BIN:$PATH" "$RUNNER"
) >"$output" 2>&1; then
  if grep -Eq 'Ran 8 tests' "$output" && grep -Eq '^OK$' "$output"; then
    ok "ran the existing eight-case unittest through the RAG virtualenv"
  else
    bad "runner did not report the expected eight-case unittest success"
    sed -n '1,120p' "$output" >&2
  fi
else
  bad "runner failed from a non-repository working directory"
  sed -n '1,120p' "$output" >&2
fi

if grep -q 'unexpected .* invocation' "$output"; then
  bad "runner invoked a sandboxed live-service or network command"
else
  ok "sandboxed docker, curl, and wget were not invoked"
fi

sect "runner implementation stays within the hermetic boundary"
if grep -qF 'REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"' "$RUNNER" \
  && grep -qF 'PY="$REPO_ROOT/rag/.venv/bin/python"' "$RUNNER" \
  && grep -qF 'exec "$PY" tests/test_charter_rag.py' "$RUNNER"; then
  ok "resolves the repository from BASH_SOURCE and execs the absolute RAG Python"
else
  bad "runner does not have the required repository-root and interpreter invocation shape"
fi

if grep -nE '(^|[;[:space:]])(source|\.)[[:space:]]|\b(docker|curl|wget)\b|rag-retrieval-test\.sh' "$RUNNER" >/dev/null; then
  bad "runner contains an environment, live-service, network, or live-suite invocation"
else
  ok "runner contains no environment source, live tooling, or live-suite invocation"
fi

sect "missing RAG interpreter fails early with setup guidance"
copy="$WORK/copied-root/tests/run-charter-rag-contract.sh"
cp "$RUNNER" "$copy"
if (
  cd "$WORK/non-repo-cwd"
  PATH="$FAKE_BIN:$PATH" "$copy"
) >"$WORK/missing-venv-output.txt" 2>&1; then
  bad "copied runner succeeded without a RAG virtualenv"
else
  status=$?
  if [ "$status" -eq 2 ] \
    && grep -q 'missing RAG virtualenv Python' "$WORK/missing-venv-output.txt" \
    && grep -q 'python3 -m venv rag/.venv' "$WORK/missing-venv-output.txt"; then
    ok "missing interpreter exits early with actionable setup guidance"
  else
    bad "missing interpreter failure was not actionable or did not exit 2"
    sed -n '1,120p' "$WORK/missing-venv-output.txt" >&2
  fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
