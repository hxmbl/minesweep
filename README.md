# MineSweep

A secrets and sensitive data scanner for code repositories. MineSweep detects credentials, API keys, passwords, and other sensitive data, then evaluates them against configurable policies to produce risk reports.

## Installation

```bash
go install github.com/minesweep/minesweep@latest
```

Or build from source:

```bash
git clone https://github.com/minesweep/minesweep
cd minesweep
go build -o minesweep ./cmd/minesweep
```

## Quick Start

```bash
# Scan current directory
minesweep .

# Scan with verbose output
minesweep -v .

# Output as JSON
minesweep --json .

# Output as SARIF (for CI/CD integration)
minesweep --sarif .
```

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
| `--verbose` | `-v` | `false` | Verbose output showing details |
| `--fail-on` | | `low` | Minimum severity that exits non-zero |
| `--min-confidence` | | `0` | Minimum confidence threshold (0.0-1.0) |
| `--min-severity` | | | Minimum severity to report |
| `--tag` | `-t` | | Filter by tag (repeatable) |
| `--diff` | `-d` | `false` | Only scan files changed vs base branch |
| `--diff-base` | | `main` | Base branch for diff comparison |
| `--staged` | `-s` | `false` | Only scan git staged files |
| `--baseline` | `-b` | | Baseline file to compare against |
| `--update-baseline` | | `false` | Update baseline with current findings |

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
minesweep --min-severity medium --max-severity critical .
```

## Output Formats

### Text (default)

```
Risk Score: High (80)

Found 3 findings across 2 types.

Critical items detected:
  • AWS Access Key ID

Safe to share publicly? No.
Safe to send to AI? No.
Review findings before sharing this file.

Files scanned: 42
Findings: 3

  [HIGH] AWS Access Key ID
    File: .env:5
    Confidence: 95%
    Reason: AWS access key pattern detected
    Action: block

  [MEDIUM] Generic Password
    File: config.yml:10
    Confidence: 70%
    Reason: password pattern detected
    Action: review
```

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

MineSweep uses YAML-based rules to detect secrets. Rules are located in the `rules/` directory:

- `aws.yml` - AWS credentials and keys
- `gcp.yml` - Google Cloud credentials
- `azure.yml` - Azure credentials
- `github.yml` - GitHub tokens and keys
- `generic.yml` - Generic patterns (passwords, API keys, etc.)
- `env.yml` - Environment variable patterns
- `private-key.yml` - Private keys and certificates

### Custom Rules

Create a YAML file in the rules directory:

```yaml
id: my-custom-rule
type: regex
severity: high
confidence: 0.9
pattern: "MY_API_KEY=[A-Za-z0-9]{32}"
reason: "Custom API key detected"
tags:
  - custom
  - api-key
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
