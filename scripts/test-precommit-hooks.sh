#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

[[ -f .pre-commit-hooks.yaml ]] || fail ".pre-commit-hooks.yaml missing"

grep -q '^- id: minesweep$' .pre-commit-hooks.yaml || fail "missing minesweep hook id"
grep -q 'id: minesweep-strict' .pre-commit-hooks.yaml || fail "missing minesweep-strict hook id"
grep -q 'entry: minesweep --staged --fail-on high \.' .pre-commit-hooks.yaml || fail "default hook entry mismatch"
grep -q 'entry: minesweep --staged --fail-on high --no-inline-suppressions \.' .pre-commit-hooks.yaml || fail "strict hook entry mismatch"
grep -q 'pass_filenames: false' .pre-commit-hooks.yaml || fail "pass_filenames must be false for staged scan semantics"
pass "pre-commit hook manifest shape"

if command -v pre-commit >/dev/null 2>&1; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  git -C "$TMP" init -q
  git -C "$TMP" config user.email test@example.com
  git -C "$TMP" config user.name test
  printf 'repos:\n  - repo: %s\n    rev: HEAD\n    hooks:\n      - id: minesweep\n' "$ROOT" > "$TMP/.pre-commit-config.yaml"
  echo 'ok' > "$TMP/clean.txt"
  git -C "$TMP" add clean.txt
  (cd "$TMP" && pre-commit run --all-files) || fail "clean pre-commit run failed"
  pass "pre-commit framework clean run"
else
  echo "SKIP: pre-commit not installed; framework integration not executed"
fi
