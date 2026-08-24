# MineSweep

A policy driven secrets and sensitive data scanner for code repositories. MineSweep detects credentials, API keys, passwords, and other sensitive data, then evaluates them against configurable policies to produce risk reports.

## Installation

Homebrew (macOS/Linux):

```bash
brew install hxmbl/tap/minesweep
```

Build from source:

```bash
git clone https://github.com/hxmbl/minesweep
cd minesweep
go build -o minesweep ./cmd/minesweep
```

## Quick Start

```bash
# Scan current directory - sensible defaults, no config needed
minesweep .

# Relaxed policy for local development
minesweep -p developer .
```

The default text report groups findings by severity, explains what each one
means, and suggests next steps. A clean scan simply prints:

```
✓ No secrets or sensitive data detected.
  Scanned 42 files in 0.8s.
```

### Getting started

```bash
minesweep init          # write a commented starter .minesweep.yml
minesweep version       # print build information (also: minesweep --version)
minesweep explain aws-access-key-id   # what a rule detects + how to respond
```

`minesweep explain` accepts exact IDs, unique prefixes, and name fragments;
run it without arguments to list every rule.

## Usage

```
minesweep [path] [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--rules` | `-r` | `rules` | Directory containing rule YAML files |
| `--policy` | | | Policy file to evaluate against |
| `--profile` | `-p` | | Profile name (developer, enterprise, public-github) |
| `--profiles` | | `profiles` | Directory containing profile YAML files |
| `--policy-dir` | | `policy` | Directory containing policy YAML files |
| `--json` | | `false` | Output as JSON |
| `--sarif` | | `false` | Output as SARIF (for CI/CD) |
| `--dashboard` | | `false` | Show rule health dashboard |
| `--annotations` | | `false` | Show GitHub Actions annotations |
| `--color` | | `auto` | When to colorize text output: `auto`, `always`, `never` |
| `--benchmark` | | `false` | Time full scans instead of writing a report |
| `--runs` | | `1` | Number of timed runs for `--benchmark` |
| `--verbose` | `-v` | `false` | Verbose output showing details |
| `--fail-on` | | `low` | Minimum severity that exits non-zero |
| `--min-confidence` | | `0` | Minimum confidence threshold (0.0-1.0) |
| `--min-severity` | | | Minimum severity to report |
| `--tag` | `-t` | | Filter by tag (repeatable) |
| `--diff` | `-d` | `false` | Only scan files changed vs base branch |
| `--diff-base` | | `main` | Base branch for diff comparison |
| `--staged` | `-s` | `false` | Only scan git staged files |
| `--history` | `-H` | `false` | Scan every unique blob across all git history |
| `--baseline` | `-b` | | Baseline file to compare against |
| `--update-baseline` | | `false` | Update baseline with current findings |
| `--workers` | `-w` | NumCPU | Number of concurrent workers |
| `--config` | | | Path to config file (default: search for `.minesweep.yml`) |
| `--suppress` | | | Suppression file to ignore specific findings |
| `--include-tests` | | `false` | Include test files in scan (skipped by default) |
| `--watch` | | `false` | Watch for file changes and re-scan automatically |
| `--watch-interval` | | `2s` | How often to check for changes in watch mode |
| `--max-files` | | `0` | Maximum number of files to scan (0 = unlimited) |
| `--memory-limit-mb` | | `0` | Maximum memory usage in MB (0 = unlimited) |
| `--max-file-size-mb` | | `0` | Maximum file size in MB to scan (0 = use default 50MB) |
| `--max-concurrent-reads` | | `0` | Maximum concurrent file reads (0 = use workers) |

### Subcommands

- `minesweep init` - Write a starter `.minesweep.yml` config file
- `minesweep version` - Print version and build information
- `minesweep explain [rule-id]` - Show what a rule detects, its patterns, and remediation guidance
- `minesweep install-hooks` - Install a git pre-commit hook that scans staged files
- `minesweep uninstall-hooks` - Remove the pre-commit hook

### Output colors

Text output is colorized on terminals only. Control it with `--color auto|always|never`;
`NO_COLOR` and `TERM=dumb` also disable colors in `auto` mode (the default). Piped or
redirected output is never colorized, so CI logs stay clean.

### Benchmark mode

Time full scans (walk → read → detect → policy) instead of writing a report:

```bash
# Single timed scan with throughput and memory stats
minesweep --benchmark .

# Five timed runs (plus one untimed warmup): min/median/mean/max
minesweep --benchmark --runs 5 .

# Machine-readable stats for regression tracking
minesweep --benchmark --json --runs 5 . > bench.json
```

Benchmark runs always exit `0` — they are not a pass/fail gate. Combine with any
scan options (`--profile`, `--diff`, `--staged`, ...) to benchmark a specific setup.

## Examples

### Basic Scanning

```bash
# Scan a directory
minesweep ./src

# Scan with minimum confidence filter
minesweep --min-confidence 0.5 .

# Scan only critical and high severity findings
minesweep --min-severity high .
```

### CI/CD Integration

```bash
# SARIF output for GitHub Actions
minesweep --sarif . > results.sarif

# Fail CI if high severity secrets found
minesweep --fail-on high .

# Only scan changed files in PR
minesweep --diff --diff-base main .
```

### Baseline Mode

```bash
# Create initial baseline
minesweep --update-baseline --baseline .minesweep-baseline.json .

# Only report new findings since baseline
minesweep --baseline .minesweep-baseline.json .
```

### Git Integration

```bash
# Scan only staged files (pre-commit)
minesweep --staged .

# Scan diff against main branch
minesweep --diff --diff-base origin/main .
```

### Filtering

```bash
# Filter by tag
minesweep --tag aws --tag gcp .

# Show only specific severity
minesweep --min-severity medium .
```

## Output Formats

### Text (default)

```
Risk score: HIGH (75/100) — not safe to share publicly or with AI tools
Found 3 findings.

1 critical  ·  1 high  ·  1 medium

block: must fix before sharing  ·  redact: value hidden  ·  warn: review recommended

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

Run with `-v` for matched values, context lines, boundary checks, and risk factors.

### JSON

```json
{
  "risk_score": 80,
  "summary": "Found 3 findings...",
  "findings": [
    {
      "type": "AWS Access Key ID",
      "severity": "critical",
      "confidence": 0.95,
      "file": ".env",
      "line": 5,
      "value": "AKIA...",
      "reason": "AWS access key pattern detected",
      "rule_id": "aws-access-key",
      "tags": ["aws", "cloud", "credentials"],
      "action": "block"
    }
  ],
  "safe_to_share": {
    "public_github": false,
    "ai_context": false
  }
}
```

### SARIF

SARIF output follows the SARIF 2.1.0 format for integration with code scanning tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [...]
}
```

## Rules

MineSweep uses YAML-based rules to detect secrets. Rules are located in the `rules/` directory.

Detection rules, the default policy, and profiles are embedded in the binary — it works out of the box from any working directory. If a `rules/`, `policy/`, or `profiles/` directory exists relative to the working directory (or is passed via flags), those on-disk files take precedence over the built-in ones.

- `aws.yml` - AWS credentials and keys
- `azure.yml` - Azure credentials
- `database.yml` - Database connection strings
- `env.yml` - Environment variable patterns
- `gcp.yml` - Google Cloud Platform credentials
- `generic.yml` - Generic patterns (passwords, API keys, etc.)
- `github.yml` - GitHub tokens and keys
- `google.yml` - Google/Firebase keys and tokens
- `jwt.yml` - JWT tokens
- `sendgrid.yml` - SendGrid, Mailgun, and Twilio keys
- `ssh.yml` - SSH private keys
- `stripe.yml` - Stripe payment API keys

### Custom Rules

Create a YAML file in the rules directory (or point `--rules` at your own):

```yaml
rules:
  - id: my-custom-rule
    type: regex
    name: My Custom API Key
    description: Custom API key detected
    severity: high
    tags:
      - custom
      - api-key
    patterns:
      - regex: "MY_API_KEY=[A-Za-z0-9]{32}"
        confidence: 0.9
```

Fields: `severity` is one of `info, low, medium, high, critical`; `confidence`
is 0.0–1.0; `capture_group` (optional) selects which regex group is reported as
the secret value. Rules are matched per line and can be filtered with
`file_filter: {include: [...], exclude: [...]}` glob lists. Verify custom rules
with `minesweep explain <rule-id>` (pass `-r <dir>` when your rules live outside
the default directory).

### Policies & profiles

Findings are evaluated against ordered policy rules; the first matching rule
wins. Each rule has a tag list (`"*"` matches everything), an action
(`allow`, `warn`, `redact`, or `block`), and an optional `min_severity`.
Invalid actions or severities fail loudly at startup rather than being
silently ignored. Profiles (see `profiles/`) may extend other profiles via
`extends:`.

### Git history

Most real leaks live in *old* commits, not the working tree. `--history` scans
every unique blob reachable from all refs and attributes each finding to the
commit that introduced it:

```bash
minesweep --history .
```

```
  [block] AWS Access Key ID
          src/config.py@9f2c1a77b0e3:12 · 95% confident · commit 4a91f02
          introduced 2025-11-03T14:22:01Z by alice
          "add deployment config"
          ↳ Rotate this key in the AWS IAM console...
```

Cost scales with content diversity, not commit count: each blob is scanned
exactly once (a secret present in 400 commits costs one scan), then flagged
objects are attributed via `git log --find-object`. Findings participate in
exit codes like any other scan, so `--fail-on` gates work in CI. Combine with
`--baseline` to silence already-handled history findings.

### Gitleaks compatibility

Drop any gitleaks TOML config into your rules directory (or point `--rules` at
it) and it loads natively — no conversion step:

```bash
cp gitleaks.toml rules/           # or: minesweep -r ~/.config/gitleaks .
minesweep --history .             # 200+ community rules, our engine
```

Supported fields: `id`, `description`, `regex`, `secretGroup` (→ capture
group), `entropy` (→ per-pattern minimum Shannon entropy), `tags`, and both
legacy (`[rules.allowlist]`) and modern (`[[rules.allowlists]]`) allowlists
with path/content regexes, stopwords, and OR/AND conditions. Global
allowlists apply to every rule in the file.

Documented divergences:
- **Severity is assigned heuristically** (gitleaks has none): private-key ids
  → critical, known provider prefixes → high, generics → medium. Imported
  findings carry the `imported-gitleaks` tag so you can filter them.
- `keywords` are advisory in gitleaks and are not used for gating here; ours
  extracts required literals from each regex automatically.
- `[extend]` (loading remote/default configs) and commit-based allowlists are
  unsupported and warn at load time.

Switching teams can keep their triage history:

```bash
minesweep import-gitleaks-ignores .gitleaksignore -o suppress.json
minesweep --suppress suppress.json --history .
```

### Suppressions

`--suppress <file>` takes a JSON file of findings to exclude:

```json
{
  "version": "1",
  "suppressions": [
    { "id": "docs-example", "rule_id": "aws-account-id", "reason": "sample data in docs" },
    { "id": "fixture", "pattern": "^test/fixtures/" }
  ]
}
```

Within one entry, any field that matches suppresses the finding: `rule_id`
matches exactly, `file` matches exactly, and `pattern` is a regular
expression applied to both the value and the file path.

## Project Structure

```
minesweep/
├── cmd/minesweep/     # CLI entrypoint (cobra commands, flags, hook install, init/version/explain)
├── config/            # .minesweep.yml config file discovery and loading
├── detectors/         # Detection implementations (regex, entropy, base64, ...)
├── engine/            # Orchestration: walk -> detect -> filter -> evaluate
├── filesystem/        # File walking, ignore patterns, diff/staged helpers
├── findings/          # Finding model, severity, risk report, baseline/suppression
├── git/               # Git operations (diff files, staged files, branch sanitization)
├── policy/            # Policy rules and profiles evaluation
├── profiles/          # Bundled policy profiles (developer, enterprise, ...)
├── report/            # Output formats (text, JSON, SARIF, dashboard, annotations) + color + remediation guidance
└── rules/             # Built-in detection rule YAML files
```

## Exit Codes

- `0` - No secrets found or all findings below `--fail-on` threshold
- `1` - Secrets found at or above `--fail-on` severity

## Development

```bash
# Run tests
go test ./...

# Build
go build ./cmd/minesweep

# Lint
golangci-lint run
```

## License

no
