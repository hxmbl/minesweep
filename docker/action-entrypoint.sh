#!/bin/sh
# Entrypoint for the GitHub Action (action.yml). INPUT_ARGS is split on
# purpose: it carries the scan flags and the target, e.g. "--fail-on high .".
set -u
git config --global --add safe.directory "${GITHUB_WORKSPACE:-/github/workspace}" 2>/dev/null || true

if [ -n "${INPUT_SARIF:-}" ]; then
    # shellcheck disable=SC2086
    minesweep --sarif --no-pager ${INPUT_ARGS} > "${INPUT_SARIF}"
else
    # shellcheck disable=SC2086
    minesweep --no-pager ${INPUT_ARGS}
fi
exit $?
