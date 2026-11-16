#!/bin/sh
# Entrypoint for the GitHub Action (action.yml).
#
# INPUT_ARGS is split on whitespace on purpose: it carries scan flags and the
# target (for example: "--fail-on high --no-inline-suppressions ."). Paths or
# arguments containing whitespace are not safely representable via this input;
# prefer scanning a workspace-relative path without spaces or invoking the
# container directly with explicit argv for advanced cases.
set -u
git config --global --add safe.directory "${GITHUB_WORKSPACE:-/github/workspace}" 2>/dev/null || true

WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
cd "$WORKSPACE" || exit 2

if [ -n "${INPUT_SARIF:-}" ]; then
    case "$INPUT_SARIF" in
      /*|../*|*/../*|..) echo "minesweep action: INPUT_SARIF must be a workspace-relative path" >&2; exit 2 ;;
    esac
    mkdir -p "$(dirname "$INPUT_SARIF")" 2>/dev/null || true
    # shellcheck disable=SC2086
    minesweep --sarif --no-pager ${INPUT_ARGS} > "${INPUT_SARIF}"
    rc=$?
else
    # shellcheck disable=SC2086
    minesweep --no-pager ${INPUT_ARGS}
    rc=$?
fi
exit $rc
