# MineSweep

A policy-driven secrets scanner for code repositories. Detects credentials, API keys, and other sensitive data, then evaluates them against configurable policies.

## Install

```bash
brew install hxmbl/tap/minesweep
```
<sub>Latest ver: v2.3.6</sub>

Or from source:

```bash
git clone https://github.com/hxmbl/minesweep
cd minesweep
go build -o minesweep ./cmd/minesweep
```

## Quick start

```bash
minesweep .                    # scan current directory
minesweep config/database.yml  # scan a single file
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
minesweep --fail-on high@60% .     # ...and confidence >= 60%
minesweep --diff --diff-base main .

# Git-scoped scans
minesweep --staged .
minesweep --history .          # every unique blob across git history

# Baseline (only report new findings)
minesweep --update-baseline --baseline .minesweep-baseline.json .
minesweep --baseline .minesweep-baseline.json .

# Filters
minesweep --min-severity high --tag aws .
minesweep --include-tests .            # test files are skipped by default
```

Test files are recognised by the conventions their languages use: `*_test.go`,
`*_spec.rb`, `test_*.py`, `spec_*.js`, and `.test`/`.spec` segments — the prefix
forms are restricted to known test-source extensions, so `test.json` and
`test.tfvars` are still scanned. Skipped files are named in the report's skip
breakdown rather than passing in silence, and `--include-tests` scans them.

Subcommands: `init`, `version`, `explain`, `install-hooks`, `uninstall-hooks`,
`trust`, `untrust`.

Run `minesweep --help` for the full flag list. Exit codes: `0` clean or below
`--fail-on`; `1` findings at or above it; `2` the scan is incomplete and its
answer is not trustworthy. See [Exit codes](#exit-codes).

---

## Behaviour changes worth knowing about

These are intentional and user-visible. Each is documented in detail in the
section linked from its entry.

- **A bare `# noqa` / `# nosec` / `# noscan` no longer suppresses anything.**
  Use `# minesweep: ignore` (optionally scoped to rule IDs), or
  `--no-inline-suppressions` in CI. A suppression that works by accident is
  indistinguishable from one that is silently failing, and the content under
  examination should not decide whether it is examined. → [Suppressing a known
  finding](#suppressing-a-known-finding)
- **A discovered config can no longer reduce coverage.** `max_file_size_mb`,
  `max_files`, `max_findings`, `memory_limit_mb`, `max_concurrent_reads`,
  `no_ignore` and the suppression/baseline/fail-on/policy keys are ignored from an
  auto-discovered `.minesweep.yml` and reported. Pass `--config` to honour them,
  or `minesweep trust <path>` — which also works from inside the pre-commit hook,
  where `--config` cannot be passed.
  → [Config trust](#config-trust)
- **Placeholders, pinned digests and names are no longer reported.** `changeme`,
  `REPLACE_ME`, `your-api-key-here`, `xxxxxxxx`, and `sha256:`-prefixed values
  are not credentials; neither is an identifier in identifier position. A
  checked-in `.env.example` went from fourteen findings to none.
  → [What is not a secret](#what-is-not-a-secret)
- **Documentation examples and comments are held to a stricter bar, not
  excluded.** Real credentials pasted into a README are still reported and still
  block. → [What is not a secret](#what-is-not-a-secret)
- **One secret now hashes to one token.** A rule that captured a whole
  assignment reported the assignment rather than the credential, so the same
  secret produced a different token per rule and the evidence line was redacted
  past the point of usefulness. `--dangerously-show-secrets` also now works for
  snippets; it previously redacted them anyway. → [What is never in a
  report](#what-is-never-in-a-report)
- **`--fail-on` accepts an optional confidence floor** (`high@60%`). A bare
  severity is unchanged. → [Gating on confidence as well as
  severity](#gating-on-confidence-as-well-as-severity)
- **A suppression entry may name a class**: `tags`, and `file` globs with `**`.
  → [Suppressing a whole class of findings](#suppressing-a-whole-class-of-findings)
- **`test_*.py` and `test_*.go` are recognised as test files**, matching the
  `--include-tests` documentation and the `test_*` convention Django and much of
  the Go ecosystem use.
- **`--history` is scoped to the requested target**, matching `--diff` and a
  single-file `--staged`. → [Git history](#git-history)
- **`--fail-on` now gates.** It previously also required a non-allow policy
  action, so `--fail-on low` could not fail on a low-severity finding.
  → [Exit codes](#exit-codes)
- **`--max-findings` output is reproducible.** Every file gets a deterministic
  share instead of racing for a shared pool, so no file is skipped wholesale.
  On a wide tree a single noisy file can now be truncated at its share.
  → [`--max-findings` and determinism](#--max-findings-and-determinism)
- **`--update-baseline` refuses to write from an incomplete scan**, and no longer
  records findings that were suppressed or dropped.
- **A single-file target no longer bypasses `--staged`/`--diff`/`--history`.**
  It used to silently scan the working tree instead of the index.
- **`install-hooks` will not overwrite a hook it did not install** (use
  `--force`, which backs the original up), and `uninstall-hooks` refuses to
  remove anyone else's. → [Pre-commit](#pre-commit)
- **Binary content never reaches a report.** A finding in a database or bundle
  now shows a descriptor instead of the file's raw bytes, in every output format.
  → [What is never in a report](#what-is-never-in-a-report)
- **Naming a binary file directly exits `2`.** Pointing minesweep at one file
  that turns out to be binary used to report "no secrets", a risk score of 0 and
  `safe_to_share: true` — having read none of it.
  → [Scanning a single file](#scanning-a-single-file)
- **Non-ASCII and renamed files are scanned in `--staged`/`--diff`.** Git's path
  quoting previously made a filename like `café-secrets.env` unmatchable, and
  `--diff-filter=ACM` skipped renames.
- **UTF-16 files are scanned**, not classified as binary.
- **An unreadable path is reported and exits `2`**, rather than producing a clean
  scan with no accounting.
- **`--rules` accepts a file as well as a directory**, and a path that does not
  exist is an error instead of a silent fallback to the built-in rules.

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

`--history` is scoped to the requested target, the same as `--diff` and the same
as `--staged` on a single file: `minesweep sub --history` reports findings only
under `sub/`. `--history` cannot be combined with `--diff` or `--staged`.

### Scanning a single file

The target may be a file rather than a directory:

```bash
minesweep .env.production          # one file
minesweep -v config/database.yml   # matched values and context
```

A named file is still filtered: `.minesweepignore` applies to it, and so do
`skip_extensions` — naming a file does not buy it an exemption. `--no-ignore` is
the override.

**Binaries are not scanned, and saying so is not the same as passing.** Content
detectors never run on binary content, so naming one reports:

```
minesweep: INCOMPLETE SCAN — results do not cover the whole target.
  - the named target is binary; its contents were not inspected and it may be unsafe

  [allow] Binary File
  app.exe:1 · 100% confident
          ↳ Binary files were skipped during scanning; secrets inside them
            (e.g. baked-in config) would not be detected.
```

That is exit `2`, not `0`. A binary holds whatever it holds, and a credential
baked into a bundle is a real leak; a scan that read none of the bytes has no
business reporting a risk score of 0 and `safe_to_share: true`. Previously it
did exactly that.

The signal is scoped to a hand-named target on purpose. In a **directory** scan
binaries are expected, are already counted in the skip breakdown
(`skipped_by`), and do not make the scan incomplete — otherwise every repository
containing a PNG would exit `2` and the code would mean nothing. `--staged`,
`--diff` and `--history` read from git rather than the working tree, so they are
unaffected.

### Pre-commit

```bash
minesweep install-hooks   # scan staged files on commit
minesweep --staged .      # or run manually
```

`install-hooks` will not overwrite a `pre-commit` hook it did not install — husky,
lint-staged and the pre-commit framework all live there. `--force` replaces one
and saves the original as `pre-commit.pre-minesweep` first. `uninstall-hooks`
refuses to remove anything it did not install.

### Suppressing a known finding

Three mechanisms, in increasing order of bluntness.

**Inline, in the file itself.** Only the explicit form is honoured:

```
# minesweep: ignore
# minesweep: ignore(aws-access-key-id, env-password)   # only these rules
```

The suppression covers the marker line and the three lines below it. A bare
`# noqa`, `# nosec` or `# noscan` is **not** recognised: those markers belong to
other tools and are written for different purposes, and honouring them lets the
content being scanned decide whether it is scanned — which mattered most in
`--staged`, where one `# noqa` silenced a critical key in the pre-commit hook.

In CI, where nothing in the repository should be able to silence itself:

```bash
minesweep --no-inline-suppressions .
```

**A suppression file.** Matching is by `rule_id`, `tags`, value regex, or path
glob:

```json
{
  "version": "1",
  "suppressions": [
    { "id": "docs-example", "rule_id": "aws-account-id", "reason": "sample data in docs" },
    { "id": "fixture", "pattern": "^test/fixtures/" },
    { "id": "all-markdown", "file": "**/*.md", "reason": "documentation only" },
    { "id": "all-db", "tags": ["database"] }
  ]
}
```

```bash
minesweep --suppress suppress.json .
```

**A baseline.** Records hashes of findings you have already triaged, so only new
ones surface. `--update-baseline` refuses to write from an incomplete scan —
a partial baseline permanently blesses findings nobody reviewed, and then every
later scan reports the tree clean. Suppressed findings are not baselined, so
removing a suppression brings its findings back.

```bash
minesweep --update-baseline --baseline .minesweep-baseline.json .
minesweep --baseline .minesweep-baseline.json .
```

Whichever you use, the count appears in the report (`findings_suppressed`), so a
gap in coverage is never invisible.

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

Verify with `minesweep explain <rule-id>`. Rules are keyed by ID, so redefining an
ID replaces the built-in rule of that name; within one directory the
alphabetically later file wins, which is how precedence is expressed.
`--rules` accepts a directory *or* a single YAML/TOML file. A path that does not
exist is an error rather than a silent fallback to the built-in rules.

Gitleaks TOML configs also load natively — drop one in your rules directory or pass `-r`:

```bash
minesweep -r ~/.config/gitleaks --history .
minesweep -r ./gitleaks.toml --history .
minesweep import-gitleaks-ignores .gitleaksignore -o suppress.json
```

Gitleaks `allowlists.paths` are matched against paths relative to the scan root,
so anchored entries such as `^docs/` work.

### Config trust

`minesweep init` writes a commented `.minesweep.yml`. A config found by walking
up from the scan target is **untrusted**, because it belongs to whatever is
being scanned, or to an unrelated project, or to a parent directory. It may not
reduce what the scan looks at:

| Ignored from a discovered config | Why |
| --- | --- |
| `max_file_size_mb`, `max_files`, `max_findings`, `memory_limit_mb`, `max_concurrent_reads` | each one skips content; a repository shipping `max_file_size_mb: 1` would have every file holding a credential skipped while the scan still reported "No secrets" and exited 0 |
| `no_ignore` | stops honouring `.minesweepignore` |
| `suppress_file`, `baseline_file`, `fail_on`, policies, profiles, `skip_extensions`, `skip_dirs` | decide what counts as a finding, or whether it counts at all |

Ignored keys are reported on stderr. Unknown keys in a discovered config are a
warning, not an error, so an unrelated project's config cannot abort a scan;
malformed YAML and type mismatches are still errors. Unknown keys in a config you
named with `--config` *are* an error, because you meant that file.

`no_inline_suppressions` is the exception and is honoured from a discovered
config: it only ever surfaces more findings, and there is no way to grant a
repository the power to suppress its own findings.

Opt in to the ignored keys explicitly:

```bash
minesweep --config .minesweep.yml .
```

CLI flags always override the config file.

#### Saying a repository is yours

`--config` is the only way above, and it has a gap: the pre-commit hook runs a
fixed command line and cannot pass a flag. So the rule that exists to make
committing a secret inconvenient was itself the reason a hook was unusable — the
remedy was to drop the hook or bypass it.

`minesweep trust` closes that, and it works from anywhere including inside the
hook:

```bash
minesweep trust            # trust the current directory
minesweep trust --list     # show what is trusted, and why
minesweep untrust .
```

The decision is stored **outside** the repository, in your own config directory,
so a checkout cannot add itself to the list. That placement is the whole point,
and it is why there is deliberately no `# minesweep: trust` marker inside the
config: a malicious repository would add that marker to the config it ships,
which is exactly the weakening the rule exists to prevent.

This is the same arrangement as `git config --global --add safe.directory`. Git
faces the identical problem — it cannot tell a repository you own from one you
just cloned — and answers it the same way, by asking you to say so explicitly and
remembering the answer somewhere the repository cannot reach.

`--verbose` reports which config was used and on what basis:

```
Using config file: /work/myrepo/.minesweep.yml (trusted)
  trusted: listed in /Users/you/Library/Application Support/minesweep/trust
```

### Gating on confidence as well as severity

`--fail-on` reads severity. Confidence is computed for every finding and shown
next to it, so a finding could block a commit while reporting itself as "60%
confident" with nothing the reader could do about it.

The second axis is available, and not imposed:

```bash
minesweep --fail-on high .          # severity >= high — the default behaviour
minesweep --fail-on high@60% .      # severity >= high AND confidence >= 60%
minesweep --fail-on high@0.6 .      # the same, as a fraction
```

A bare severity is unchanged, so no existing pipeline changes behaviour.

It is not the default because no threshold separates a documentation sample from
a real leak: the 0.60 that makes `webhook_secret = "…"` in a README fence look
like an example is the same 0.60 that makes `password = "…"` in a config file
look like one. That difference is in the surrounding grammar, so it belongs in
the detector, not in the gate.

Findings that clear the severity bar but not the confidence bar do not block,
and are **named on stderr** rather than dropped in silence — a gate that lets
something through quietly is the failure this mechanism exists to avoid:

```
minesweep: not gating 1 finding(s): at or above high severity but below 90% confidence.
  docs/example.env:4 · 85% confident · High Entropy String
  To gate on these too, lower the floor: --fail-on high
```

### What is not a secret

Some values are not credentials, and the grammar around them often says so
plainly. MineSweep uses that, because a gate that reports fourteen findings on
seven lines of obviously-fake configuration is a gate that gets deleted — and
`git commit --no-verify` is the bypass everything else here exists to make
unnecessary.

**Values that declare themselves.** `changeme`, `REPLACE_ME`, `placeholder`,
`your-api-key-here`, `xxxxxxxx`, `dummy-value-not-real`. A checked-in
`.env.example` full of these produces no findings. Dictionary words are *not*
treated this way: `password=administrator` is a weak real password, and a
scanner that stays quiet about it is not doing its job.

**Pinned digests.** `sha256:9f86d081…` is a content address, not a bearer token —
the prefix is the author asserting what the value is, and no provider issues
credentials in that shape.

**Vendor documentation stand-ins.** AWS's published key pair, matched in full.
Matching them exactly is what makes this safe; a substring rule would be defeated
by padding an attacker's key with the word "example".

**Names, not values.** A long identifier in identifier position is a name:
followed by `(`, preceded by a definition keyword, or preceded by `.`. This is
what stops

```python
def test_backend_asks_about_the_library_without_importing_it(monkeypatch):
```

from being reported as a 70%-confident secret — the line contains the substring
`key` inside `monkeypatch` and the name is 52 characters long. No entropy
threshold can tell that from a secret; the grammar settles it.

**Documentation examples and comments, held to a stricter bar.** These are
*not* excluded — real credentials do get pasted into READMEs, and excluding
`*.md` would trade a false positive for a silent gap. Instead, text that is
describing a credential rather than being one must clear a higher bar:

| Context | Bar |
| --- | --- |
| Code, config, anywhere else | the normal confidence floor |
| Inside a fenced block, indented code block, inline code span, or HTML comment in a doc file | 0.80 |
| On a comment-only line | 0.90 |

So a `ghp_…` or `AKIA…` pasted into a README is still reported and still blocks,
while `webhook_secret = "…"` at 0.60 in a fence is not. An unmarked `AKIA…` in a
comment is still reported at 0.95.

### Suppressing a whole class of findings

Per-finding suppression spends a baseline budget that does not grow and records
no reason. For a finding that recurs by construction, that is the wrong
granularity — each occurrence costs a separate decision and stops none of the
next. A suppression entry may therefore name a class:

```yaml
version: "1"
suppressions:
  # Every finding from one rule.
  - id: keyword context in docs
    rule_id: env-password
    file: "docs/**/*"

  # Every finding carrying a tag.
  - id: connection strings
    tags: [database]

  # Just these two.
  - id: docs tokens only
    rule_id: env-token
    file: "docs/**/*.env"
```

Populated fields intersect; `file` accepts `**` and, with no separator, matches
at any depth (`*.md`). A `file` value with no wildcard keeps its old exact-match
meaning, so existing suppression files behave identically.

A suppression file cannot be set from a discovered `.minesweep.yml` — that would
be handing a repository the power to silence itself. Use `--suppress` on the
command line, which is also what the pre-commit hook would need.

### JSON output

```bash
minesweep --json .
```

`severity` is an **integer**, not a name: `0` info, `1` low, `2` medium, `3` high,
`4` critical, `5` block. `value` is a `sha256:<12 hex>` token, not the secret —
pass `--dangerously-show-secrets` only when you have already decided the output
is safe to share.

```json
{
  "risk_score": 75,
  "summary": "Risk Score: high (75)\n\nFound 2 findings across 2 types.\n\n...",
  "findings": [
    {
      "type": "AWS Access Key ID",
      "severity": 5,
      "confidence": 0.95,
      "file": "a.env",
      "line": 1,
      "column": 19,
      "value": "sha256:1a5d44a2dca1",
      "reason": "block: Amazon Web Services access key ID (AKIA/ASIA format)",
      "rule_id": "aws-access-key-id",
      "tags": ["aws", "cloud", "credentials"],
      "action": "block",
      "context": "> AWS_ACCESS_KEY_ID=sha256:1a5d44a2dca1\n  \n",
      "source_line": "AWS_ACCESS_KEY_ID=sha256:1a5d44a2dca1"
    }
  ],
  "reasons": ["block: Amazon Web Services access key ID (AKIA/ASIA format)"],
  "safe_to_share": {
    "public_github": false,
    "ai_context": false,
    "ci_pipeline": false,
    "email": false
  },
  "boundaries": null,
  "files_scanned": 8,
  "files_failed": 0,
  "duration_ms": 10,
  "bytes_scanned": 9362
}
```

A scan that did not cover everything adds its own accounting. These fields are
present only when they apply:

| Field | Meaning |
| --- | --- |
| `incomplete` | the results are not a complete answer to the question asked |
| `incomplete_reasons` | each way the scan fell short |
| `unreadable_paths` | paths that could not be opened, so nothing is known about their contents |
| `findings_suppressed` | removed by an inline comment or the suppression file |
| `findings_discarded` | **at least** this many were dropped by a per-file budget; detectors stop before materialising the rest, so the true figure is higher |
| `findings_dropped` | dropped by the final `--max-findings` trim |
| `skipped_by` | per-cause breakdown of files not inspected |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | clean, or findings below `--fail-on` |
| `1` | at least one finding at or above `--fail-on` |
| `2` | **the scan is incomplete** — the answer is not trustworthy |

Exit 2 outranks the findings check. A caller that receives 2 must not read it as
"clean". It fires on a truncated scan, an unreadable path, an exhausted memory or
finding budget, `--max-files` stopping early, or a [named target that turned out
to be binary](#scanning-a-single-file).

`--fail-on` is a severity threshold and nothing more: it fires on any finding at
or above it, regardless of what the policy decided to do with it.

### What is never in a report

Two guarantees, enforced at the point where content enters a finding rather than
at the point where it is printed:

- **A finding never carries raw binary bytes.** Content detectors do not run on
  binary files, so a credential in a database, a bundle or a single-line JSON
  blob has no finding value to censor — and the evidence attached to a finding
  with no value used to bypass redaction entirely, so the whole first "line" of
  the file reached the report. Binary content is withheld and replaced with a
  descriptor, in every output format including `--dangerously-show-secrets`.
- **Evidence is bounded and censored.** Each rendered line is capped at 512
  bytes, cut on a rune boundary, because "a line" is not bounded by anything: a
  30 MB input produced a 60 MB report. The finding's own value is replaced by a
  stable `sha256:` token everywhere it appears — the value, the source line and
  the context — so equal values produce equal tokens, which is what baselines
  depend on.

That last guarantee is the one a reader leans on hardest, so it is worth being
precise about how it is obtained. Two things had to be true, and both now are:

- **The value reported is the credential, not the regex match.** A rule that
  captures an assignment reports the value half of it, while still pointing at
  the line. Reporting the match meant one secret produced a *different* token
  per rule — three findings for one `APP_SECRET` yielded three hashes — so "equal
  values produce equal tokens" was false, and a reader could not tell "the same
  secret in two places" from "two different secrets".
- **Censoring happens once, at the output boundary.** The engine decides the
  policy action and hands the value through; `report.CensorReport` does the
  censoring for every output format at once. Censoring inside the renderer as
  well meant the heuristic ran twice over the same text, and because it is not
  idempotent the same source line rendered differently for each finding that
  referenced it. It also made `--dangerously-show-secrets` a no-op for snippets:
  the renderer redacted what the flag had asked to reveal, and the legend still
  said "value hidden" while doing it.

Terminal control sequences are stripped from every attacker-controlled string:
file paths, git author names, commit messages, rule names and descriptions, and
the labels in the skip breakdown. Newlines are neutralised in single-line fields,
so a filename cannot forge a line that reads as part of the report.

### Benchmark

```bash
minesweep --benchmark .                # single timed run
minesweep --benchmark --runs 5 --json . > bench.json
```

Benchmark runs always exit `0` — they are not a pass/fail gate.

### SARIF

`--sarif` emits SARIF 2.1.0 with `invocations[].executionSuccessful` and a
`properties` block, so a **partial** scan is distinguishable from a complete one
in the uploaded artifact — the exit code carries the truth, but code-scanning
consumers read the file. A truncated scan also carries an error-level
`toolExecutionNotifications` entry per reason, and `executionSuccessful: false`.

### `--watch`

```bash
minesweep . --watch --watch-interval 2s
```

Output redirected into the watched tree is identified by device and inode and
excluded, so `--watch . > report.txt` does not retrigger on its own report.

### `--max-findings` and determinism

Identical input produces byte-identical output in every field but the timings,
independent of `--workers`. Above the cap each file is allowed a deterministic
share (`cap / file count`); the previous shared pool raced between workers, so
which files were admitted varied per run, whole files were skipped without being
opened, and every reported counter moved.

The trade-off is deliberate: on a wide tree a very noisy single file can be
truncated at its share, and the cap can be under-filled. `--max-findings 0`
removes the cap entirely.

---

## Development

```bash
go test ./...
go test -race ./...
go build ./cmd/minesweep
golangci-lint run
```

### Test fixtures: never write a credential-shaped literal

GitHub's push protection rejects the **whole push** if any committed file
contains a credential-shaped token, and it does not care that the file is a
test. The failure is invisible until then:

```
remote: - Push cannot contain secrets
remote:      —— Amazon AWS Access Key ID ———
remote:        paths: engine/engine_test.go:37
```

Two ways to write a fixture that a detector will accept:

**Build it from fragments** — `internal/fixtures` provides well-formed fictional
values for every vendor shape:

```go
body := "AWS_ACCESS_KEY_ID=" + fixtures.AWSAccessKeyID() + "\n"
```

**Or escape the first character.** Go interprets `\xNN` in an interpreted string
literal, so the decoded value is byte-identical and the detector still sees
exactly what it must, while the raw file no longer contains the token:

```go
// AKIAZQ4TLN2XRH7JWBVG
body := "AWS_ACCESS_KEY_ID=\x41KIAZQ4TLN2XRH7JWBVG\n"
```

Both are checked. `TestNoCredentialShapedLiteralInAnyGoSource` walks every `.go`
file in the repository and fails on any unescaped token, so the convention cannot
rot — but the raw-string and comment cases are the ones it will catch first, since
neither can hold a `\xNN` escape.

Do not use a vendor's published documentation credentials as a stand-in for "a
real secret". They are allowlisted by GitHub, so they push cleanly, which is
exactly the problem: a suppression or a fixture tuned to `AKIAIOSFODNN7EXAMPLE`
looks like it is handling a credential *class* when it is handling two literals,
and a real AWS key in a real file gets the same treatment. `internal/fixtures`
exists so that distinction does not have to be made by eye.

## License

no
