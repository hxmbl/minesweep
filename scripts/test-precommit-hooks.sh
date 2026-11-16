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
grep -q 'always_run: true' .pre-commit-hooks.yaml || fail "always_run must be true for staged scan semantics"
pass "pre-commit hook manifest shape"

if command -v pre-commit >/dev/null 2>&1; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  git -C "$TMP" init -q
  git -C "$TMP" config user.email test@example.com
  git -C "$TMP" config user.name test
  printf 'repos:\n  - repo: %s\n    rev: HEAD\n    hooks:\n      - id: minesweep\n' "$ROOT" > "$TMP/.pre-commit-config.yaml"

  mkdir -p "$TMP/dir with spaces"
  echo 'ok' > "$TMP/dir with spaces/clean file.txt"
  git -C "$TMP" add .
  (cd "$TMP" && pre-commit run --all-files) || fail "clean staged run with spaces failed"

  # staged credential should fail
  # Assemble the fixture at runtime so the repository's own secret scan does
  # not mistake this test data for a committed credential.
  token_prefix="$(printf '%b' '\x67\x68\x70\x5f')"
  token_suffix='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  printf 'const TOKEN = "%s";\n' "${token_prefix}${token_suffix}" > "$TMP/dir with spaces/secret.js"
  git -C "$TMP" add "dir with spaces/secret.js"
  if (cd "$TMP" && pre-commit run --all-files); then
    fail "expected secret to fail pre-commit hook"
  fi
  pass "pre-commit framework staged/space/secret behavior"
else
  echo "SKIP: pre-commit not installed; framework integration not executed"
fi
