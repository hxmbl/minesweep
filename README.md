# MineSweep

A policy-driven secrets scanner for code repositories. Detects credentials, API keys, and other sensitive data, then evaluates them against configurable policies.

## Install

```bash
brew install hxmbl/tap/minesweep
```

Or from source:

```bash
git clone https://github.com/hxmbl/minesweep
cd minesweep
go build -o minesweep ./cmd/minesweep
```

## Quick start

```bash
minesweep .                    # scan current directory
minesweep -p developer .       # relaxed policy for local work
minesweep init                 # write a starter .minesweep.yml
minesweep explain aws-access-key-id
```

Rules, the default policy, and profiles are embedded — it works out of the box. A clean scan prints:

```
✓ No secrets or sensitive data detected.
  Scanned 42 files in 0.8s.
```

## Common usage

```bash
# CI / GitHub Actions
minesweep --sarif . > results.sarif
minesweep --fail-on high .
minesweep --diff --diff-base main .

# Git-scoped scans
minesweep --staged .
minesweep --history .          # every unique blob across git history

# Baseline (only report new findings)
minesweep --update-baseline --baseline .minesweep-baseline.json .
minesweep --baseline .minesweep-baseline.json .

# Filters
minesweep --min-severity high --tag aws .
```

Subcommands: `init`, `version`, `explain`, `install-hooks`, `uninstall-hooks`.

Run `minesweep --help` for the full flag list. Exit `0` if clean (or below `--fail-on`); `1` otherwise.

---

## Showcases

### What a finding looks like

```
Risk score: HIGH (75/100) — not safe to share publicly or with AI tools
Found 3 findings.

1 critical  ·  1 high  ·  1 medium

CRITICAL ──────────────────────────────────────────────────
  [block] AWS Access Key ID
          .env:5 · 95% confident
          ↳ Rotate this key in the AWS IAM console, remove it from the file, and purge it from
            git history (e.g. git filter-repo). Consider switching to short-lived IAM roles.

MEDIUM ────────────────────────────────────────────────────
  [warn] Generic Password
          config.yml:10 · 70% confident
          ↳ Change this password and load it from an environment variable or secrets manager
            instead of hardcoding it.

──────── Next steps ────────────────────────────────────────
  • Already aware of these? Silence them with:
      minesweep --update-baseline --baseline .minesweep-baseline.json .
  • Show matched values and context:
      minesweep -v .
```

Use `-v` for matched values, context lines, and risk factors. Prefer `--json` or `--sarif` for machines.

### CI / GitHub Actions

```bash
minesweep --sarif . > results.sarif   # upload to code scanning
minesweep --fail-on high .            # gate the build
minesweep --diff --diff-base main .   # only files changed in the PR
minesweep --annotations .             # inline PR annotations
```

### Git history

Most real leaks live in old commits, not the working tree. `--history` scans every unique blob and attributes each finding to the commit that introduced it:

```bash
minesweep --history .
```

```
  [block] AWS Access Key ID
          src/config.py@9f2c1a77b0e3:12 · 95% confident · commit 4a91f02
          introduced 2025-11-03T14:22:01Z by alice
          "add deployment config"
```

Each blob is scanned once (a secret in 400 commits costs one scan), then attributed via `git log --find-object`. Combine with `--baseline` to silence already-handled history findings.

### Pre-commit

```bash
minesweep install-hooks   # scan staged files on commit
minesweep --staged .      # or run manually
```

### Baseline & suppressions

Track known findings so only new ones surface:

```bash
minesweep --update-baseline --baseline .minesweep-baseline.json .
minesweep --baseline .minesweep-baseline.json .
```

Or suppress specific findings with a JSON file:

```json
{
  "version": "1",
  "suppressions": [
    { "id": "docs-example", "rule_id": "aws-account-id", "reason": "sample data in docs" },
    { "id": "fixture", "pattern": "^test/fixtures/" }
  ]
}
```

```bash
minesweep --suppress suppress.json .
```

### Custom rules

Point `--rules` at a directory of YAML rule files:

```yaml
rules:
  - id: my-custom-rule
    type: regex
    name: My Custom API Key
    severity: high
    tags: [custom, api-key]
    patterns:
      - regex: "MY_API_KEY=[A-Za-z0-9]{32}"
        confidence: 0.9
```

Verify with `minesweep explain <rule-id>`. Gitleaks TOML configs also load natively — drop one in your rules directory or pass `-r`:

```bash
minesweep -r ~/.config/gitleaks --history .
minesweep import-gitleaks-ignores .gitleaksignore -o suppress.json
```

### Config trust

`minesweep init` writes a commented `.minesweep.yml`. Auto-discovered configs from the scanned tree are **untrusted**: performance keys apply, but security-relevant keys (`suppress_file`, `baseline_file`, `fail_on`, policies, etc.) are ignored with a warning — a repo shouldn't be able to weaken its own scan. Opt in explicitly:

```bash
minesweep --config .minesweep.yml .
```

CLI flags always override the config file.

### JSON output

```bash
minesweep --json .
```

```json
{
  "risk_score": 80,
  "findings": [
    {
      "type": "AWS Access Key ID",
      "severity": "critical",
      "confidence": 0.95,
      "file": ".env",
      "line": 5,
      "rule_id": "aws-access-key",
      "action": "block"
    }
  ],
  "safe_to_share": { "public_github": false, "ai_context": false }
}
```

### Benchmark

```bash
minesweep --benchmark .                # single timed run
minesweep --benchmark --runs 5 --json . > bench.json
```

Benchmark runs always exit `0` — they are not a pass/fail gate.

---

## Development

```bash
go test ./...
go build ./cmd/minesweep
golangci-lint run
```

## License

no
