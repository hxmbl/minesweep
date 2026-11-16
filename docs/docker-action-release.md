# Docker image and GitHub Action release semantics (STRM-652)

## Image base and contents
- Runtime image: `alpine:3.21` (security-supported at time of change; review regularly).
- Includes `git` so `--diff`, `--staged`, and `--history` work inside container scans.
- Includes `/usr/local/bin/minesweep-action` entrypoint used by the GitHub Action.

## Tag semantics
- Stable release `vX.Y.Z`: publish immutable `ghcr.io/hxmbl/minesweep:vX.Y.Z` (and typically `vX.Y`).
- Moving aliases: `ghcr.io/hxmbl/minesweep:vX` and `ghcr.io/hxmbl/minesweep:latest` are convenience aliases for the newest **stable** release line (not prereleases).
- Prereleases: publish exact prerelease tag only (no `latest`, no major alias updates).

## GitHub Action versioning
- `action.yml` is a composite action that runs the container image.
- Exact action refs (e.g. `uses: hxmbl/minesweep@v2.4.3`) resolve to `ghcr.io/hxmbl/minesweep:v2.4.3` by default for deterministic scanner behavior.
- Major/moving refs (e.g. `@v2`, `@main`) resolve to `ghcr.io/hxmbl/minesweep:v2` unless `inputs.image` is set explicitly.
- Advanced override: set `with.image` to pin a specific image digest/tag.

## Input/argument contract
- `inputs.args` is passed through shell word splitting by design (flags + target). Paths/arguments containing whitespace are not safely representable via this string input; use workspace-relative paths without spaces or run the container directly with explicit argv.
- `inputs.sarif` must be a workspace-relative path; the entrypoint rejects absolute and `..` traversal paths.

## CI security defaults
- Default action args include `--no-inline-suppressions` so repository-controlled inline suppression comments cannot bypass the CI gate. Remove/override only with explicit intent.
