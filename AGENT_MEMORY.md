# Handoff: MineSweep bug-bounty remediation

Everything below is from my own session memory. I have no shell/file access in this instance, so I cannot re-verify any of it. I've marked **[VERIFIED]** for things I personally ran and observed output from, **[REPORTED]** for findings from the user's own note or from subagent audits I did not personally re-run, **[HYPOTHESIS]** for reasoning I never confirmed, and **[PLANNED]** for work I intended but did not do.

---

## 1. Original mission

**Phase 1 (complete):** Run a bug bounty pass on MineSweep at `/Users/hxmbl/Projects/minesweep`. Explore the whole app. Look for real bugs, security issues, data-loss risks, broken edge cases, regressions. Prioritise things that could actually affect users. Reproduce issues where possible and trace to root cause. For each finding report: severity, exact location, what happens, repro steps, likely cause, suggested fix. Investigate rather than assume when something looks suspicious. **Do not make changes yet — findings first.**

**Phase 2 (in progress, interrupted):** Fix the entire report. Explicit instructions:
- Explore the repository properly first; understand architecture across detector pipeline, filesystem walker, policy/config loading, reporting/sanitisation, CLI, CI, tests, and their interactions.
- Trace reported bugs to actual root causes; **look for other places affected by the same underlying mistake**.
- For every finding: verify behaviour yourself before changing it; understand what assumptions existing code makes; check for the same pattern elsewhere; fix the underlying design rather than adding a narrow special case; preserve correct intended behaviour.
- Be especially careful with **false negatives, scan coverage, secret disclosure, trust boundaries, symlinks, sanitisation, exit codes**.
- If the report's proposed fix is wrong or incomplete, use judgement.
- If two findings share a root cause, fix them together.
- Priority order given: (1) #1 gate/Unicode; (2) #2 secret leakage; (3) #3 finding-budget; (4) #4–#7 coverage/trust/symlink/walker; (5) #8 calibration; (6) #9–#10 ignored/test files; (7) #11–#21 correctness; (8) then #22–#38.
- **"Do not interpret that ordering as permission to ignore related lower-priority bugs you discover while fixing something."**
- **"Don't turn this into a giant rewrite. MineSweep is supposed to stay simple. Prefer small, structural fixes."**
- Add regression tests for every fixed bug where practical; test actual failure modes not happy paths; include adversarial cases for security-sensitive fixes; don't write pointless tests for trivial refactors. Run relevant tests continuously then full suite. Run race detection where relevant. Re-run the reproduced scanner cases from the report after fixes.
- Verify specifically: real secret still detected; credential-shaped identifier with no value is not; Unicode case-folding cannot bypass a high/critical detector; snippet output cannot expose neighbouring secrets; symlink chains cannot escape scan root; coverage-affecting skips accounted for and cannot silently produce clean exit; finding limits actually limit memory/work; output deterministic; baselines contain what was actually reported; terminal output cannot be controlled by repository content or git metadata.
- **"Do not modify the repository until you've explored enough to understand the architecture."** Then implement. Don't just give a plan. **"Keep going until the fixes are implemented and verified."**
- Final report: what was fixed, what deliberately not fixed and why, tests/checks run, new issues genuinely outside this pass. **"No corporate summary. No giant essay."**

**User's own emphasis on #8:** "Get that one genuinely correct. Credential-shaped variable names must not become findings merely because an identifier happens to be called `token` or `api_key`, and assignment rules must not consume the next line. At the same time, don't weaken legitimate secret detection just to make the numbers look nicer."

**Context:** MineSweep was being evaluated as a **replacement for gitleaks**. A prior comparison (the user's note) found detection breadth a tie (15/15 planted credentials) but calibration badly off: 104 low findings on a clean repo, 99 of them `generic-api-key`; at `--min-severity medium` only 4 findings, all false positives. Recommendation was: fix the two detector defects, then swap, keeping gitleaks as a shadow scan for one release cycle.

---

## 2. Repository understanding

Go module `minesweep`, ~76 `.go` files, ~9,336 lines non-test. Branch `main` @ `70291d0`. Deps: `spf13/cobra`, `spf13/pflag`, `BurntSushi/toml`, `zeebo/blake3`, `gopkg.in/yaml.v3`. Build: `go build -o minesweep ./cmd/minesweep`. `assets.go` embeds `rules/`, `policy/`, `profiles/` via `//go:embed`-style `minesweep.Assets`.

### Packages and files

**`cmd/minesweep/`** — CLI entry.
- `main.go` (767 lines). Cobra root, `Args: cobra.ExactArgs(1)`. `PersistentPreRunE` validates `--fail-on` / `--min-severity` **then** calls `loadConfig`. Global `var cfg engine.Config` plus `outputJSON/outputSARIF/...`, `configPath`, `watchMode`, `toolVersion` (set via ldflags).
- `configField` struct + `configFields` slice — the config trust table. Each entry has `label`, `flag`, `secure bool`, `isPath bool`, `apply`, `present`. `secure: true` means "ignored when the config was auto-discovered, unless `--config` given". `applyConfigValues()` implements this and prints a warning listing ignored labels.
- `strField` / `numField` / `pathField` constructors. `pathField` resolves relative paths against `filepath.Dir(cfgPath)`.
- `runScan`, `scanAndReport` (censors via `report.CensorReport` unless `DangerouslyShowSecrets`, emits INCOMPLETE banner to **stderr**, returns exit 2 for incomplete, 1 for findings ≥ `--fail-on` and `Action != ActionAllow`).
- `exitCodeError` carries exit codes through cobra so defers run.
- `runWatch`, `runInstallHooks`, `runUninstallHooks`, `hasPreCommitHook`, `preCommitHook` const.
- `renderTextInteractive` in `pager.go` (110 lines): pages only when TTY and not watch; `resolvePagerCommand()` honours `MINESWEEP_PAGER`, `GIT_PAGER`, `PAGER`, default `less -FRX`; EPIPE swallowed.
- `benchmark.go` (273 lines), `subcommands.go` (421 lines: `init`, `import-gitleaks-ignores`, `version`, `explain`), `help.go` (141 lines: `renderGroupedHelp` with sections + unlabelled leftover), `config_trust_test.go`, `pager_test.go`, `benchmark_test.go`, `import_test.go`, `main_test.go`.

**`engine/engine.go`** (1126 lines) — orchestration.
- `Config` struct with all knobs. `DefaultConfidenceFloor = 0.05`, `DefaultMaxFindings = 25000`, `DefaultMaxFileSize = 50MB`.
- Incomplete reasons const block: `ReasonMemoryLimit`, `ReasonFindingCap`, `ReasonFileBudget`, `ReasonWorkerPanic`, `ReasonMaxFiles`.
- `Engine` with atomics `filesScanned/bytesScanned/filesSkipped/filesFailed/findingsKept/findingsDropped`, `mu`-guarded `incompleteReasons`, `skipStatsMu`-guarded `skipStats`.
- `New(cfg)`: builds detector list `[regex, filetype, symlink, entropy, base64, database, oauth]`, resolves policies, creates `readSemaphore`.
- `resolvePolicies` precedence: explicit `--profile` > explicit `--policy` file > `<policy-dir>/default.yml` on disk if dir exists > embedded `policy/default.yml`. Uses `dirOrEmbedded` for profiles.
- `Run(path)` resets counters, calls `run`, then stamps report stats.
- `run` → `runSingleFile` / `runDiff` / `runHistory` / `runDirectory`.
- `finalize(root, allFindings)`: `relativizeFindings` → `dedupFindings` → `filterBaseline` (which also calls `updateBaseline`) → `filterSuppressions` → `trimToConfidenceCap` → `evaluate` → `sortFindings` → `GenerateRiskReport`.
- `detect(file)`: `defer file.Release()`, `GetContent()`, budget arming, `readSemaphore` acquire, run all detectors, confidence/severity/tag filtering, inline suppression, `attachEvidence`, `findingsKept.Add`.
- `detectParallel(files)`: worker pool, result channel, memory-limit monitor goroutine, panic recovery with `noteIncomplete(ReasonWorkerPanic)`.
- `withinDir` (EvalSymlinks both sides), `relativizeFindings` (plain `strings.TrimPrefix` — **no EvalSymlinks**), `trimToConfidenceCap`, `dedupFindings`, `sortFindings`, `evaluate` (applies `RedactValue`, scrubs raw value from SourceLine/Context), `hasAnyTag`.

**`filesystem/`**
- `file.go` (387 lines). `File` struct: `Path, Content, Size, Mode, IsSymlink, SymlinkTarget, IsBinary, Hash, MaxContentBytes, FindingBudget, FindingBudgetHit` + private `contentLoaded, contentErr, contentMu, lowered, lineIdx, symlinkState, loader`.
- `symlinkState` enum: `symlinkOK, symlinkUnreadable, symlinkUnsafe, symlinkBroken`.
- `newFileFromInfo`: for symlinks builds **lexical** `absTarget = filepath.Join(filepath.Dir(path), target)`, calls `isSafePath(absTarget, root)`, `os.Stat` for real size, marks broken only on `os.IsNotExist`.
- `contentLocked`: pre-populated `Content` wins; then `loader` (git blobs); then unsafe/broken/unreadable symlink → `[]byte{}` with **nil error**; else `readBounded`.
- `readBounded`: `io.ReadAll(io.LimitReader(fh, MaxContentBytes+1))`, error if over.
- `ClaimFinding()` / `SetFindingBudget(n)` — the broken budget.
- `Release()` clears Content/lowered/lineIdx/Hash under `contentMu`.
- `ContentHash` BLAKE3, `LoweredContent` = `bytes.ToLower` (**ASCII-only** — root cause of #1), `Lines()` lazily builds `LineIndex`.
- `isSafePath(path, root)` uses `strings.HasPrefix(rel, "..")`.
- `walker.go` (988 lines). `IgnoreFileNames = [".minesweepignore", ".msignore"]`. `ignoreRule{pattern, negate, dirOnly, anchored}`. `NewIgnorePattern`, `parseIgnoreRule`, `ignoreRule.matches`, `IgnorePattern.decide` (last match wins), `Ignored`, `Rules`.
- `globMatch`/`matchGlobParts` with `**` support, **no memoisation**.
- `ancestorDirs`, `pathBase`, `relUnder`.
- `LoadIgnoreFile`, `LoadIgnoreForDir` (merges both filenames), `LoadMinesweepIgnore`.
- `ignoreSearchDirs(start)` — walks up, bounded by `runGitTopLevel` (shells out to `git rev-parse --show-toplevel`); if that fails `stop` stays `""` → walks to `/`.
- `DiscoverIgnore(root)` — **concatenates all ancestor lines into one `IgnorePattern`** used as base.
- `IgnoreSet{base, nested}`, `AddNested(dir, p)` with `key := strings.Trim(filepath.ToSlash(dir), "/")` and an `if key == ""` merge branch, `Ignored(rel)` iterating `ancestorDirs(rel)`.
- `DefaultSkipExtensions` (includes `.png`, `.lock`, `.sum`, `.min.js`, `".DS_Store?"` — the `?` is a glob that never matches under `==`), `DefaultSkipDirs` (`.git`, `node_modules`, `vendor`, `dist`, `build`, `target`, `out`, `tmp`, `coverage`, …), `DefaultMaxFileSize = 50MB`.
- `SkipReason` consts: `SkipReasonIgnore, SkipReasonExt, SkipReasonTest, SkipReasonLarge, SkipReasonSkipDir, SkipReasonVCS`. `WalkStats` with `SkippedIgnore/Ext/Test/Large/Symlink/Vendor/Kept`, `ByReason`, `Examples`, `MaxExamples`.
- `WalkOption{Stats, Ignore, IgnoreFilePath, MaxFileSize, OnError, SkipExtensions, SkipDirs, IncludeTestFiles, NoIgnore, ignoreRoot}`. **`OnError` is never set by any caller** — grep confirmed only `help.go`'s unrelated `ContinueOnError`.
- `newFilterSet`: the `strings.Contains(e[1:], ".")` panic site for empty extension.
- `isTestFile`.
- `filterSet.reason` / `reasonExcludingSkipDir`; `SkipChecker` with `Classify`, `ClassifyRel`, `ShouldSkip`, `classify`, `ShouldSkipSize`, `MaxSize`, `relLabel`.
- `lines.go` (86 lines): `LineIndex{content, starts}`, `NewLineIndex`, `LineCol`, `LineCount`, `LineText`, `Context(center, radius)` — prefixes `"> "` on centre, `"  "` elsewhere, **TrimSpace per line**.
- `filetype.go` (154 lines): `textExtensions`, `binaryExtensions`, `IsTextFile`, `IsBinaryFile`, `binaryMagics`, `IsBinary` (`binarySampleSize = 8192`, NUL byte or >10% control chars), `IsUTF8`, `HasBOM` (detects utf-8/utf-16-le/utf-16-be). **`IsUTF8`, `HasBOM`, `IsTextFile`, `IsBinaryFile` are dead code — never called anywhere.**
- `symlink_state_test.go`, `path_regression_test.go`, `filesystem_test.go`, `watcher_race_test.go`, `file_fuzz_test.go`.

**`detectors/`**
- `detector.go` (15 lines): `Detector` interface + `maxMatchesPerPattern = 10000`.
- `regex.go` (402 lines): `RuleFile`, `Rule{ID,Type,Name,Description,Severity,Tags,Patterns,FileFilter,Allowlist}`, `Pattern`, `FileFilter`. `NewRegexDetector(rulesDir)` — embedded rules are the base, on-disk **merges over**, `getUserRulesDir()` (`$XDG_CONFIG_HOME/minesweep/rules` or `~/.config/minesweep/rules`) merges last. `Detect` builds `lowered := file.LoweredContent()`, runs `pat.safeMatch`, `ClaimFinding`, copies tags. `Pattern.compile()` sets `gate = extractLiteralGate`. `loadRulesFS` reads `.yml/.yaml/.toml`, warns on invalid severity and per-pattern compile failure, drops rules whose every pattern failed. `mergeRules(defaults, users)` replaces by ID. `matchesFileFilter` uses `filepath.Match` on basename.
- `gate.go` (~200 lines): `gateAlt{alts, altBytes, fold}`, `gateBranch`, `literalGate`, `satisfied`, `containsAny`, `maxGateBranches = 64`, `extractLiteralGate`, `collectRequired`, `crossJoin`, `mergeAdjacentLiterals`. **This is where I added `asciiFoldLiteral`.**
- `entropy.go` (194 lines): `secretKeywords` regexp, `extractStringsRe = [A-Za-z0-9\-_+=/]{20,}`, `shannonEntropyBytes` (fixed 256-slot table), `computeEntropyConfidence`, thresholds `entropyMedium=4.0/High=4.5/VeryHigh=5.0`, emits `RuleID: "entropy-high"`, `SeverityLow`.
- `base64.go` (261 lines): `base64Candidate{value,start,end}`, `maxBase64Candidates = 1000`, builds a synthetic `filesystem.File` with `Path + " (base64 decoded)"`, `remap` maps decoded offsets back, prefixes `Type` with `base64_`. Calls `decodedFile.SetFindingBudget(file.FindingBudget)`.
- `database.go` (141 lines): `dbPattern`, `newDBPattern`, patterns for postgres/mysql/mongodb/redis/generic URLs, `database_credentials_kv`, `sql_connection_string`, `jdbc_connection_string`.
- `oauth.go` (131 lines): `oauthPattern`, `newOAuthPattern`, patterns for oauth/client secret, access token, gitlab, bitbucket, session cookie, cloud storage.
- `filetype.go` (55): emits `binary-file-detected` / `executable-file-detected`, both `SeverityInfo`.
- `symlink.go` (39): emits `symlink-detected`, `SeverityInfo`, `Value: file.SymlinkTarget`.
- `gitleaks.go` (315 lines): `GitleaksConfig`, `GitleaksRule`, `GitleaksAllowlist`, `LoadGitleaksRules` (conflicts warned; `extend` unsupported; `keywords` ignored; `Confidence: 0.8` hardcoded; tags `imported-gitleaks` + original + `gitleaks`), `gitleaksSeverity` heuristics, `buildAllowlistSet`, `compileGitleaksAllowlist`, `suppressedByAllowlist`, `suppressesBlock` (OR/AND condition, `regexTarget`, stopwords).
- **`value.go` — NEW FILE I CREATED.** See §4.
- `value_test.go` — NEW, mine.

**`findings/`**
- `finding.go`: `Finding` struct with `Type, Severity, Confidence, File, Line, Column, Value, Reason, RuleID, Tags, Action, Context, SourceLine, Commit, Author, Date, CommitSummary`.
- `severity.go`: `Severity` int 1..5 (`info`…`critical`), `ParseSeverity` (unknown → info), `IsValidSeverity`, `Action` consts, `RiskScore` 0/25/50/75/100, `RedactValue(value, ruleName) string { return "<REDACTED>" }` (ignores both args).
- `baseline.go`: `historyDisplaySuffix = regexp.MustCompile("@[0-9a-f]{12}$")`, `normalizeBaselineFile`, `Baseline{Version, Findings map[string]string}`, `BaselineEntry{File,Line,RuleID,Value}`, `FindingHash` (SHA-256 of JSON), `LoadBaseline` (missing file → empty), `SaveBaseline` (0644), `FilterNewFindings`, `UpdateBaseline`, `GetBaselineStats`, `splitLocation`.
- `suppress.go`: `Suppression{ID,RuleID,File,Line,Pattern,Reason}`, `SuppressionList`, `LoadSuppressions` (**`json.Unmarshal` only**), `SaveSuppressions`, `FilterSuppressed`, `compilePatterns`, `isSuppressed` (all populated fields must match; `Pattern` matches `f.Value` or normalized `f.File`), `filterByEntries`.
- `inline.go`: `inlineIgnoreRe` (`minesweep: ignore(rule-ids)`), `inlineIgnoreAltRe` (`nosec|noscan|noqa` at EOL), `FilterInlineSuppressionsLines` (walks up to 3 lines above), `isSuppressedAt`.
- `risk.go`: `RiskReport` struct incl. `Incomplete`, `IncompleteReasons`, `FindingsDropped`, `SkippedBy`, `FilesScanned/Skipped/Failed`, `BytesScanned`, `DurationMs`. `GenerateRiskReport`, `computeRiskScore` (critical+private-key → critical), `computeSafeToShare`, `buildSummary`.

**`policy/policy.go`**: `PolicyRule{Tags,Action,Reason,MinSeverity}`, `Evaluate` (first matching rule wins, `*` wildcard tag), `defaultAction` (critical→block, high→redact, medium→warn, else allow), `ValidateRules`, `LoadPolicyFile(FS)`, `ResolveProfileFS`, `resolveProfileWithSeenFS` (child actions prepended, parent appended; cycle detection).

**`policy/default.yml`** and **`profiles/{default,developer,enterprise,public-github}.yml`** — duplicated sources of truth. `policy/default.yml` has 9 rules including `tags:["api-key"] action: redact`; `profiles/default.yml` has 8 (no `api-key`). `developer.yml` extends default with `["*"] min_severity: high → warn` then `["env"] → allow` (the `env/allow` is dead for high+ because `*` is evaluated first).

**`report/`**
- `output.go` (459 lines): `WriteText`, `writeCleanReport`, `writeHeader`, `writeCoverageNotes`, `writeIncomplete`, `writeCounts`, `writeLegend`, `writeGroups`, `writeFinding` (the big one), `writeBoundaries`, `writeRiskFactors`, `writeNextSteps`, `groupBySeverity`, `sectionHeader`, `wrapText`, `splitLines`, `textWriter`.
- `sanitize.go` (371 lines): `SanitizeTerminal`, `needsEscape`, `CensorValue`, `SecretToken` (sha256, `tokenPrefix="sha256:"`, `tokenLength=12`), `isCensoredToken`, `CensorFinding`, `CensorReport`, `censorAllValues`, `secretCandidate = [A-Za-z0-9][A-Za-z0-9_.:/=-]{7,}[A-Za-z0-9]`, `censorSecretSubstrings`, `looksLikeSecret` (unique-ratio > 0.6), `HighlightSyntax` (emits raw ANSI unconditionally), `isWordChar`.
- `sarif.go` (154): `WriteSARIF` builds `ruleList` map ruleID→index, `severityToSARIFLevel` (critical+high→error, medium→warning, else note), `StartLine: f.Line` with **no clamp**.
- `annotations.go` (123): `GenerateAnnotations` (ignores `f.Action`), `WriteGitHubAnnotations` (sanitizes `\n\r` → `_`/` `, strips `::`), `WriteGitHubWorkflowSummary` (**dead in CLI**), `extractRuleID`, `WriteAnnotationsToFile` (**dead**).
- `dashboard.go` (151): `GenerateDashboard` (per-rule Severity from first finding only), `WriteDashboard` (**no SanitizeTerminal anywhere**).
- `remediate.go` (109): `ruleRemediations` map keyed by **dashed** rule IDs, `tagRemediations`, `RemediationText(ruleID, tags)` (first matching tag wins), `remediationFor`.
- `color.go` (85): `ColorMode`, `ParseColorMode`, `colorEnabled` (resolves NO_COLOR / TERM / isTerminal), `palette` with `wrap` guarding on `enabled`.

**`git/git.go`** (178): `SanitizeBranchName` (`^[a-zA-Z0-9][a-zA-Z0-9\-_.\/]*$` — first char must be alnum, which blocks `--flag` injection), `TopLevel`, `GetDiffFiles` (probes `rev-parse --verify` then `git diff <base>...HEAD`, falls back to empty-tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904`), `GetStagedFiles` (`--diff-filter=ACM`), `GetIndexContent`, `GetFileContent` (rejects absolute/`..` paths), `parseFileList`, `IsGitRepo`, `ReadFileLines`.

**`git/history.go`** (299): `HistoryObject`, `shaPattern = ^[0-9a-f]{7,64}$`, `ValidSHA`, `ListHistoryObjects` (rev-list --all --objects + cat-file --batch-check), `batchChecker`, `BlobFetcher` (cat-file --batch, mutex-serialized, hands out copies, `blobBufRetainBytes = 1<<20`), `FindOriginCommit` (`git log --all --find-object=` with `--format=%H%x00%an%x00%aI%x00%s`, takes the **last** line as oldest).

**`config/config.go`** (103): `FileConfig` with `yaml`+`json` tags including `DangerouslyShowSecrets` (field exists, **never in `configFields` so never applied**). `configNames = [".minesweep.yml", ".minesweep.yaml", "minesweep.yml", "minesweep.yaml"]`. `FindConfig` walks **to `/`** with no git-root bound. `LoadFile` uses `dec.KnownFields(true)` — unknown keys are a hard error. `FindAndLoad`.

**`rules/*.yml`** — 12 files: aws, azure, database, env, gcp, generic, github, google, jwt, sendgrid, ssh, stripe. Format: `{id, type: regex, name, description, severity, tags, patterns: [{regex, confidence, capture_group?, min_entropy?}], file_filter?}`.

**CI / packaging:** `.github/workflows/ci.yml` (`permissions: contents: write` at top level; jobs test/lint/build/build-macos/release; golangci-lint-action@v4 with `version: latest` + `install-mode: goinstall` — verified from run logs this silently resolves to **v1.64.8**; goreleaser-action@v6), `.github/workflows/minesweep.yml` (`permissions: contents: read` + `security-events: write`; `--diff --diff-base ${{ github.base_ref }}`; a **second** full scan for SARIF under `continue-on-error: true`), `Dockerfile`, `.goreleaser.yaml`, `.golangci.yml` (**v1 schema, no `version:` key → hard-fails on golangci-lint v2**), `.msignore` (ignores `rules/`, `README.md`, `detectors/database.go`, `git/git.go`, `*_test.go`, `minesweep`, `dist/`), `.gitignore`.

### How a scan flows
`main` → `engine.New(cfg)` (load rules, policies, build detectors) → `engine.Run(path)` → mode dispatch → `filesystem.WalkWithOptions` (or git file lists) → `detectParallel` → per-file `detect` (load content, arm budget, run detectors, filter by confidence/severity/tag, inline suppression, attach evidence) → `finalize` (relativize, dedup, baseline, suppress, trim, evaluate, sort, report) → `report.CensorReport` → text/JSON/SARIF/annotations/dashboard → exit code.

### Things that were correct and must be preserved
- `findings.FilterNewFindings` / `UpdateBaseline` hash **pre-redaction** values on purpose (comment: "Filtering deliberately happens BEFORE evaluation so that baselines and suppression patterns match raw secret values, not redacted ones").
- `SanitizeTerminal` exists and is used at most print sites (the gaps are specific).
- `CensorValue`/`SecretToken` design (hash, not prefix) is deliberate and good.
- Exit code 2 for incomplete scans, distinct from 1.
- RE2 means no catastrophic backtracking — `safeMatch`'s comment is correct.
- Inline suppression, `--staged` index-content loading (correctly catches staged-then-deleted files), `--history` blob dedup.

---

## 3. Bug-bounty findings

Severity as I originally assigned. "Fixed" = I changed code and verified. Everything else is untouched.

### #1 — Unsound regex literal gate → silent false negatives **[CRITICAL] — FIXED]**
- **Problem:** `Pattern.safeMatch` derives a necessary-literal precondition and returns `nil` **without running the regex** if the gate fails. For `(?i)` literals the gate lowercases with `strings.ToLower` and searches `file.LoweredContent()`, which is `bytes.ToLower` — **ASCII-only**. But Go's `regexp` `(?i)` uses Unicode *simple folding*: `(?i)s` matches `U+017F` (ſ, LATIN SMALL LETTER LONG S) and `(?i)k` matches `U+212A` (KELVIN SIGN).
- **Impact:** in ASCII exactly two letters break this — `k` and `s`. A file using either homoglyph in a credential keyword is skipped entirely for that rule. Lost rules included `aws-secret-key` (**CRITICAL**), `env-password`, `database-password`, `generic-password`, `database_credentials_kv`.
- **Root cause:** ASCII-only lowering vs Unicode folding; gate used as a hard precondition rather than a hint.
- **Files:** `detectors/gate.go:98-104` (fold case in `collectRequired`), `filesystem/file.go:360` (`bytes.ToLower` in `LoweredContent`), `detectors/regex.go:225-230` (`safeMatch` gate short-circuit).
- **Fix implemented:** `asciiFoldLiteral` refuses to emit a folded gate unless every rune's entire `unicode.SimpleFold` orbit is ASCII. Otherwise no gate for that sub-expression (sound, just slower).
- **Dependencies:** none. Independent of #8.
- **Extra dimension I found:** the gate is evaluated over the **whole file**, so whether a secret is detected depends on unrelated text elsewhere in the same file (case C in my repro).

### #2 — `-v` / `--snippets` prints adjacent secrets in full **[CRITICAL] — UNTOUCHED, was next**
- **Problem:** three compounding sub-bugs:
  - (a) `looksLikeSecret` requires `uniqueChars/len > 0.6`. Hex/base32 secrets have ≤16 distinct symbols so the ratio collapses with length (32-hex → 0.375, 64-hex → 0.25) and they are **never censored**.
  - (b) `secretCandidate = [A-Za-z0-9][A-Za-z0-9_.:/=-]{7,}[A-Za-z0-9]` omits `@ $ % ^ & * + ! ~ ?`. A credential containing one is fragmented; fragments below 9 chars produce no candidate, and the **prefix gets tokenized while the remainder prints verbatim**.
  - (c) Only the finding's own value is exact-matched; other secrets in the ±2-line context are caught only by the (broken) heuristic.
  - (d) Multi-line `f.Value` defeats exact replacement because `LineIndex.Context` TrimSpaces each line independently.
  - (e) `CensorFinding` early-returns entirely when `isCensoredToken(f.Value)`, so anything shaped like `sha256:0123456789ab` disables all censoring of the evidence.
  - (f) `--snippets` **re-hashes the already-hashed token** (`output.go:222,242`): `Value:` shows `sha256:1a5d44a2dca1`, the snippet two lines below shows `sha256:aa637c84d177` for the same secret.
- **Why it matters:** the tool's own next-steps hint says *"Show hashed values and context: `minesweep -v .`"*. Following the tool's advice to share a report leaks neighbouring credentials. Observed: `SIGNING_HASH=d41d8cd98f00b204e9800998ecf8427e` and a 64-char hex token printed in full, 19 occurrences; and `admin_password=P@ssw0rd$ecret!2024` → `sha256:8def970b126f@ssw0rd$ecret!2024` (23 of 24 chars leaked) with **no flags required** beyond `--snippets`.
- **Root cause:** inferring "is this a secret" from evidence text with a heuristic tuned for high-alphabet random strings, instead of using the set of secrets the engine already knows about.
- **Files:** `report/sanitize.go:150, 256-257, 104-114, 137-145`; `filesystem/lines.go:82`; `report/output.go:222, 242`.
- **Depends on:** nothing, but interacts with #25 (redact token) and #26 (ANSI).

### #3 — `ClaimFinding` never denies; per-file finding budget entirely dead **[CRITICAL] — UNTOUCHED]**
- **Problem:**
  ```go
  func (f *File) ClaimFinding() bool {
      if f.FindingBudget <= 0 { return true }   // 0 means "unlimited"
      if f.FindingBudgetHit || f.FindingBudget <= 0 { f.FindingBudgetHit = true; return false }
      f.FindingBudget--
      return true
  }
  ```
  The decrement reaches 0 exactly when the budget is spent, and 0 then reads as "unlimited". Probe output: budget 3 → `claim 1..3 = true`, then `claim 4..8 = true, budget=0, hit=false`. So `FindingBudgetHit` can never become true and `ReasonFileBudget` (`engine.go:44, 871`) is **unreachable**.
- **Measured:** 10 MB file + `--max-findings 1` → **394 MB peak RSS, 299,966 findings materialised**. 15 MB file → 55,387 findings. `--max-findings 1/100/25000` → 123/130/200 MB.
- **Root cause:** overloading 0 as both "unlimited" and "exhausted".
- **Files:** `filesystem/file.go:285-295`; `engine/engine.go:44, 850-871`; `detectors/base64.go:200, 208, 222`; `detectors/{regex,database,oauth,entropy}.go` `ClaimFinding` calls.
- **Planned fix:** shared thread-safe counter (see §7.3).

### #4 — Untrusted `.minesweep.yml` can disable large-file scanning, exit 0 **[CRITICAL] — UNTOUCHED]**
- **Problem:** `max_file_size_mb` is classified `secure: false` ("performance"), but it reduces coverage and — unlike `max_files`/`max_findings`/`memory_limit_mb` — never sets `Incomplete`. Repro: 7.2 MB `.env` containing an AWS key + `.minesweep.yml` containing only `max_file_size_mb: 1` → `✓ No secrets or sensitive data detected.`, exit 0.
- **Root cause:** trust model classes coverage-reducing keys as safe.
- **File:** `cmd/minesweep/main.go:259-271`.
- **Verified** the contrast: `max_files`, `max_findings` do set `Incomplete`; `memory_limit_mb` didn't trigger on a tiny tree; `include_low_confidence` harmless.
- **Fix:** mark `max_file_size_mb` (and arguably `max_files`, `max_findings`, `memory_limit_mb`) `secure: true`.

### #5 — Scanning a symlinked directory scans nothing, exit 0 **[CRITICAL] — UNTOUCHED]**
- **Problem:** `filepath.WalkDir` does not follow the root symlink, so the root is treated as one non-directory entry → `newFileFromInfo` marks `symlinkUnsafe` → `contentLocked` returns `[]byte{}`. The `symlink-detected` finding is `SeverityInfo` → `defaultAction` → `ActionAllow`, so it never trips `--fail-on`. `filesScanned` counts it.
- **Repro:** `wrapper/project -> ../realproject` containing an AWS key + `DB_PASSWORD`; `cd wrapper && minesweep project` → `Risk score: NONE (0/100)`, exit 0, `files_scanned: 1`. Trailing slash behaves the same. Control `minesweep ../realproject` → 6 findings.
- **Aggravating:** `--diff`/`--staged`/`--history` *do* resolve symlinks (via `git.TopLevel`/`EvalSymlinks` in `withinDir`), so the three modes disagree about the same tree.
- **Files:** `filesystem/walker.go:678`; `filesystem/file.go:145-152, 236-240`.
- **Planned fix:** `EvalSymlinks` the scan root in `engine.run` when `os.Lstat(path)` reports a symlink, so stat/walk/relativize all use the resolved path.

### #6 — Two-hop symlink chain escapes the scan root **[CRITICAL] — UNTOUCHED]**
- **Problem:** `isSafePath(absTarget, root)` validates only the **lexical first hop** (`filepath.Join(filepath.Dir(path), target)`), while `os.Stat` and `os.Open` follow the entire chain in the kernel.
- **Repro:** `outside/secret.env` (AWS key) ← `root/b.env -> ../outside/secret.env` ← `root/a.env -> b.env`. `minesweep root` reports `aws-access-key-id` on `a.env`. Single hop is correctly blocked.
- **Why it matters:** a hostile checkout can make the scanner read `~/.aws/credentials`, `~/.config/gitleaks.toml`, etc., and report rule hits, line/column, and — under `--dangerously-show-secrets` — contents.
- **Files:** `filesystem/file.go:146` vs `:266`.
- **Related sub-issues (from subagent, I did NOT verify):** symlink loops return `ELOOP` not `ENOENT` so `os.IsNotExist` misses them and state stays `symlinkOK` with no marker; a symlink to a directory gets the directory's size and is misclassified as a file.

### #7 — Unreadable directories skipped with zero accounting **[CRITICAL] — UNTOUCHED]**
- **Problem:** `WalkOption.OnError` is declared and invoked at three sites in `walkWithOptions` but **never set by any caller** (grep confirmed). An unreadable subtree vanishes with no `files_skipped`, no `files_failed`, no `SkippedBy`, no `Incomplete`.
- **Repro:** `open/a.env` readable with an AWS key, `blocked/b.env` `chmod 000` with an AWS key → `files_scanned: 1, files_skipped: null, files_failed: null, incomplete: null`.
- **Contradicts** the module's own contract at `walker.go:479-482`.
- **Files:** `filesystem/walker.go:597, 678-684, 693-698, 756-762`; `engine/engine.go:778`.
- **Fix:** always set `OnError` from the engine; route into `WalkStats` + `filesFailed` + `Incomplete`. Probably add a `ReasonUnreadable` const.

### #8 — Credential-shaped identifiers with no credential value; `generic-api-key` calibration **[CRITICAL] — FIXED]**
Full detail in §4. Sub-parts:
- **(8a)** Assignment rules accept any 8+ non-space chars as a value. `token = state.get("token")` → `env-token` 0.65; `api_key = lookup("api_key")` → `env-api-key` 0.75.
- **(8b)** `\s*` spans newlines, so `!= token:` at end of line captures the **next line**. Finding reported at line 3 of a 4-line file with `source_line` containing no value and `value` being `"position"` from line 4.
- **(8c)** `generic-api-key` = `\b([A-Za-z0-9\-_]{40,45})\b` conf 0.10 + `\b([0-9a-fA-F]{32})\b` conf 0.15, both above `DefaultConfidenceFloor` (0.05), matching every long identifier / truncated git SHA / content hash. 37 of 75 findings on the spf13 corpus; the user's note said 99 of 104 on their repo.
- **Files:** `rules/env.yml`, `rules/database.yml`, `rules/generic.yml`, `rules/{aws,azure,gcp}.yml`, `detectors/database.go`, `detectors/oauth.go`, `detectors/regex.go`.

### #9 — Ancestor `.minesweepignore` flattened into one root-anchored set **[HIGH] — UNTOUCHED]**
- **Problem:** `DiscoverIgnore` concatenates every ancestor's lines into a single `IgnorePattern` applied against the scan-root-relative path. Git anchors each pattern to its declaring directory, so merging makes each pattern more aggressive at every level above the root. `/secrets/` at repo root wrongly also drops `app/secrets/db.env`.
- **Files:** `filesystem/walker.go:364-386`, `:65`.
- **Secondary (subagent, unverified):** if `runGitTopLevel` fails, `ignoreSearchDirs` walks to `/`, defeating the stated repo-root bound.
- **Planned fix:** keep one `IgnorePattern` per directory with its own base; evaluate each against the path relative to its own directory; apply shallowest-first with last match winning.

### #10 — `*.test.*` / `*.spec.*` dropped as test files **[HIGH] — UNTOUCHED]**
- **Problem:** `isTestFile` does `TrimSuffix(base, filepath.Ext(base))` then checks `_test`, `.test`, `.spec`. `filepath.Ext` returns the suffix from the **last** dot, so the `.test`/`.spec` branches only fire for `<stem>.test.<ext>`. Traced truth table: `foo.test` no, `foo.spec` no, `foo.test.js` yes, `foo.spec.ts` yes, `foo_test.go` yes, `foo_spec.rb` **no**.
- **Impact:** `prod.test.tfvars` and `secrets.test.json` (Terraform env files that routinely carry live credentials) dropped by default as "test-file".
- **Note:** I originally reported this as *low* (dead code, scans more than expected). The subagent found the opposite and more dangerous direction; I upgraded it to **high**.
- **Planned fix:** require a known test-source extension for the `.test`/`.spec` segment form; keep `_test`/`_spec` for any extension.

### #11 — Non-deterministic output above `--max-findings` **[HIGH] — UNTOUCHED]**
- **Problem:** `trimToConfidenceCap` breaks ties on input order; input order is `detectParallel`'s result-channel completion order. Comments at `engine.go:333-335` and `:381-382` both claim determinism.
- **Measured:** 10 identical runs over an unchanged 600-finding tree (60 files × 10 AWS keys), `--workers 8 --max-findings 100` → **7 distinct result sets**.
- **Fix:** `sortFindings` *before* `trimToConfidenceCap`; tiebreak `(confidence desc, file, line, column, rule_id, value)`.

### #12 — `--update-baseline` records findings that were never reported **[HIGH] — UNTOUCHED]**
- **Problem:** `filterBaseline` runs before trimming and before suppression, and `updateBaseline` is handed the untrimmed slice. 300 findings with `--max-findings 50` → 50 reported, **300 written to the baseline**; next run prints "No secrets or sensitive data detected", exit 0. Same with `--suppress` (suppressed findings get baselined, so removing the suppression file doesn't bring them back).
- **Files:** `engine/engine.go:403-417`, `302-331`.

### #13 — `rules/`, `policy/`, `profiles/`, `--policy-dir` resolve against the CWD **[HIGH] — UNTOUCHED]**
- **Problem:** `runScan` resolves the four directory flags against `os.Getwd()`, not `scanPath`. A `policy/default.yml` in the CWD with `tags:["*"] action: allow` turned a `block` finding into `allow` → exit 0 on an unrelated target.
- **Aggravating:** feeds the terminal-injection vector (#14) and the drift between `policy/default.yml` and `profiles/default.yml`.
- **File:** `cmd/minesweep/main.go:477-488`.

### #14 — Terminal escape injection from rule descriptions, filenames and git metadata **[HIGH] — UNTOUCHED]**
- **Problem:** unsanitised print sites: `output.go:194` (`f.Author`), `:197` (`f.CommitSummary`) — both git-controlled; `:309` (`report.Reasons`); `:273` (`f.Reason`); `:101` (`report.SkippedBy`); all of `dashboard.go`.
- **Verified repro:** commit with `GIT_AUTHOR_NAME=$'Alice \033[31mRED\033[0m\033]8;;http://evil.example\033\\CLICK'` and message `$'add creds \033[2J\033[31mFAKE-CRITICAL: 1 critical finding\033[0m'` → `minesweep --history . | cat -v` emits `by Alice ^[[31mRED^[[0m^[]8;;...` and `"add creds ^[[2J^[[31mFAKE-CRITICAL..."`. ESC[2J clears the screen; OSC-8 is a clickable attacker-chosen URL. `FAKE-CRITICAL` survived verbatim (count 2).
- **Widest reach:** `SkippedBy` echoes filenames and prints on a **clean** scan, before any secret is found. A filename containing `\n` forges whole report blocks (also `f.File`/`f.Type` pass through `SanitizeTerminal`, which preserves `\n`/`\t`).
- **Related:** `SanitizeTerminal` doesn't escape C1 (U+0080–U+009F); only 7-bit forms are neutralised because ESC → `\e`. Guaranteed impact is line-break spoofing via U+0085/U+2028/U+2029.

### #15 — `--diff`/`--staged` leak absolute local paths **[HIGH] — UNTOUCHED]**
- **Problem:** `relativizeFindings` uses a plain `strings.TrimPrefix` with no `EvalSymlinks`, while `withinDir` (`engine.go:1071-1086`) does resolve. `git rev-parse --show-toplevel` resolves symlinks; `filepath.Abs(".")` prefers `$PWD`. On macOS `/tmp` → `/private/tmp`.
- **Repro:** `PWD=/tmp/ms-repro/sym`, git top `/private/tmp/ms-repro/sym` → SARIF `artifactLocation.uri = /private/tmp/ms-repro/sym/new.env`; `::error file=/private/tmp/...`; baseline records `"/private/tmp/ms-repro/sym/new.env:1"` vs `"new.env:1"` from a tree scan. Same hash appears in `--staged` for a staged-then-deleted file.
- **Why it matters:** SARIF uploads land nowhere; baselines become machine-specific, defeating "baselines match across machines".

### #16 — `install-hooks` silently destroys an existing third-party pre-commit hook **[HIGH] — UNTOUCHED]**
- **Problem:** `os.WriteFile(hookPath, …, 0755)` with no existence check, no ownership check, no `--force`. Verified a husky-style hook was replaced and success reported. Asymmetry: `uninstall-hooks` *does* verify ownership (`main.go:757`); `init` *does* guard with `--force`.
- **Fix:** refuse to overwrite a non-minesweep hook unless `--force`; consider `.bak`.

### #17 — Panic on empty `skip_extensions` entry **[HIGH] — UNTOUCHED]**
- **Problem:** `strings.Contains(e[1:], ".")` on `e == ""` → `panic: runtime error: slice bounds out of range [1:0]` at `filesystem/walker.go:833`. Go panics exit **2**, colliding with the deliberate incomplete-scan code.
- **Reachable** only via `--config` (trusted), since `skip_extensions` is `secure: true`.
- **Fix:** guard `e != ""`; validate the list; return a clean error.

### #18 — YAML suppression files rejected but `init` recommends them **[HIGH] — UNTOUCHED]**
- **Problem:** `LoadSuppressions` uses `json.Unmarshal` only. `minesweep init`'s template says `# suppress_file: .minesweep-suppress.yml`. Following the tool's own instructions aborts the scan: `error: scan: load suppressions: invalid character 'v' looking for beginning of value`, exit 1. `findings.Suppression` carries dead `yaml:` tags.
- **Fix:** accept YAML (JSON is a subset), or change the template to `.json` and drop the dead tags.

### #19 — UTF-16 files classified binary → all content detectors skipped, exit 0 **[HIGH] — UNTOUCHED]**
- **Problem:** `IsBinary` sees NUL bytes in UTF-16 and returns true; every content detector early-returns. `HasBOM` (which detects utf-16-le/be) and `IsUTF8` are **dead code**. Verified: BOM'd and BOM-less UTF-16LE `.env` with an AWS secret key → only `binary-file-detected` (info/allow), exit 0, `incomplete: null`.
- **Fix:** decode BOM'd UTF-16 to UTF-8 in `contentLocked`; use `HasBOM`/`IsUTF8`.

### #20 — `.gitleaks.toml` is never auto-discovered **[HIGH] — UNTOUCHED]**
- **Corrected finding.** The user's original note said `[allowlist]` isn't applied. **I tested it and that is wrong**: `-r` on a dir *without* the allowlist → finding fires; `-r` on a dir *with* `[allowlist]` → correctly suppressed. `LoadGitleaksRules` does `global := buildAllowlistSet(cfg.Allowlists, cfg.Allowlist, …)` and appends it to every rule's blocks.
- **The real defect:** grep confirms **no** code path reads `.gitleaks.toml`, `gitleaks.toml`, or `~/.config/gitleaks`. Only `~/.config/minesweep/rules` is automatic (`getUserRulesDir`). `.gitleaksignore` is handled solely by the explicit `import-gitleaks-ignores` subcommand. README says "drop one in your rules directory **or pass `-r`**", which reads as if the ecosystem config is picked up.
- **Interaction:** compounding #23 (`-r <file>` silently ignored), so a migrating user gets neither rules nor allowlist, silently.
- **Design tension I noted:** an allowlist from an *untrusted* repo would let a repo weaken its own scan — same class as #4. So repo-provided `.gitleaks.toml` should contribute **rules only**; allowlists honoured only when explicitly passed via `--rules`. Must be documented loudly.

### #21 — Rule "overrides" within one rules directory don't override **[HIGH] — UNTOUCHED]**
- **Problem:** `regex.go:69-70` claims *"Overrides (on-disk, then user) replace rules that share an ID."* `mergeRules` is only applied **across** sources (embedded → disk dir → user dir), never **within** `loadRulesFS`, which just appends.
- **Repro:** `r/10-base.yml` (`dup-rule`, severity high, conf 0.90) + `r/20-override.yml` (`dup-rule`, severity low, conf 0.10) → `minesweep explain dup-rule -r ./r` prints `2 rules match`; scan reports `type='BASE version' severity=4 conf=0.9`. Override silently dead.
- **Why it matters:** directly blocks the "tune a noisy rule down" workflow the gitleaks migration depends on.
- **Fix:** dedupe by ID within `loadRulesFS`, last-wins (so filename ordering expresses precedence, matching `fs.ReadDir` sorted order).

### #22 — `--max-concurrent-reads` is a no-op for reads **[MEDIUM]**
- `engine.go:839` (`GetContent`) runs **before** `engine.go:861-864` acquires the semaphore. Measured on 32 × 2.6 MB files: `--workers 1 --max-concurrent-reads 1` → 171 MB; `--workers 32 --max-concurrent-reads 1` → **1585 MB**. Fix: acquire before `GetContent`.

### #23 — `-r <file.toml>` silently ignored **[MEDIUM]**
- `detectors/regex.go:76-87`: `os.Stat` + `IsDir()` gate. A file path falls to embedded rules with no warning. Same for a typo'd path. Fix: accept a single file; error loudly on an unresolvable explicit `--rules`.

### #24 — `--snippets` re-hashes the already-hashed token **[MEDIUM]**
- `report/output.go:222, 242`. Computed: `sha256("sha256:1a5d44a2dca1")[:12] = aa637c84d177`. Breaks the advertised same-secret→same-token correlation. Inverted: correct only under `--dangerously-show-secrets`.

### #25 — Every `redact`-action finding shows the identical token `sha256:1d31bdafd1e9` **[MEDIUM]**
- `RedactValue` returns the constant `"<REDACTED>"` for all inputs (`findings/severity.go:102`), then `CensorFinding` hashes that constant. Labelled *"hashed; --dangerously-show-secrets to reveal"* but revealing yields `<REDACTED>`. All high-severity default-redact findings collapse to one identifier.

### #26 — `--snippets` writes raw ANSI into redirected files **[MEDIUM]**
- `output.go:232,242` gate on `opts.Color != ColorNever` (requested) not `p.enabled` (resolved). Measured **34 ESC bytes** with default `--color auto` redirected to a file; `--color never` → 0. Fix: gate on `p.enabled` or pass an `enabled` flag into `HighlightSyntax`.

### #27 — `SanitizeTerminal` doesn't escape C1 controls **[MEDIUM]**
- `report/sanitize.go:47`. U+0080–U+009F pass through, including U+009B (CSI), U+009D (OSC), U+0090 (DCS), U+0098 (SOS), U+009E (PM), U+009F (APC). Terminal exploitability unverified; unconditional impact is line-break spoofing.

### #28 — `--benchmark` writes the baseline file **[MEDIUM]**
- Shares global `cfg`; documented as "instead of writing a report" and always exit 0. Writes N+1 times including the untimed warmup. Verified: `--benchmark --update-baseline --baseline b.json .` created `b.json`.

### #29 — `--benchmark --json` silently switches schema **[MEDIUM]**
- `benchmark.go:93`; `findings` becomes an **integer**. `jq '.findings[0]'` → `Cannot index number with string`. README:214's "always exit 0" is also false (wrapped errors propagate to exit 1).

### #30 — Custom YAML rule typo in `confidence` → silent drop **[MEDIUM]**
- `detectors/regex.go:29-47`: `yaml.Unmarshal` without `KnownFields`; `Pattern.Confidence` unvalidated. `confidnce: 0.9` → 0.0 → below `DefaultConfidenceFloor` → finding dropped with zero output and zero warnings. Verified. `filefilter` (for `file_filter`) and `allowlist:` in a YAML rule (`Rule.Allowlist` is `yaml:"-"`, gitleaks-only) are also silently ignored. Severity **is** validated loudly — extend that to confidence and use `KnownFields`.
- **Interaction with #8:** I fixed the *built-in* calibration, but this is the same class for user rules.

### #31 — An untrusted discovered config can abort the scan **[MEDIUM]**
- `config/config.go:83` (`KnownFields(true)`) + `main.go:433`. Unknown key or malformed YAML in a discovered `.minesweep.yml` → `error: load config file: …`, exit 1. `FindConfig` walks to `/` so a stray ancestor `minesweep.yml` hard-fails everything beneath it.

### #32 — VCS-pruned files invisible in coverage reporting **[MEDIUM]**
- `walker.go:490, 510, 587-590`. `SkipReasonVCS` declared and printable but never noted by the walker. `WalkStats.SkippedSymlink` declared, summed into `TotalSkipped()`, **never incremented anywhere**. Same contract violation as #7.

### #33 — `HasPrefix(rel, "..")` misclassifies in-root names **[MEDIUM]**
- `file.go:86`, `walker.go:953`. A real file named `..env` is treated as outside root: a symlink to it is marked unsafe (no content), and in `--diff`/`--staged`/`--history` it is dropped as `SkipReasonVCS`. Correct idiom already exists at `walker.go:349`: `rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))`.

### #34 — `skip_extensions` entry without a leading dot is a no-op **[MEDIUM]**
- `walker.go:836`: `["env"]` becomes a `skipExtSet` key that can never equal `filepath.Ext()` (always dot-prefixed). Also `".DS_Store?"` at `walker.go:457` is compared with `==` so its glob intent is dead.

### #35 — Remediation text can downplay critical findings **[MEDIUM]**
- `report/remediate.go:98`: rule text wins over the `SeverityCritical` fallback, so `twilio-account-sid` (critical) prints *"Account SIDs are identifiers, not secrets, but confirm no matching auth token was committed alongside it."* Separately, all 14 `database.go`/`oauth.go` rule IDs use **underscores** while `ruleRemediations` uses **dashes**, so **none match** and they degrade to generic tag text.

### #36 — `--dangerously-show-secrets` in no `--help` section **[MEDIUM]**
- `help.go:16-41` vs `:99-108`; falls into the unlabelled leftover block below "Performance".

### #37 — `.golangci.yml` is v1 schema **[MEDIUM]**
- README's `golangci-lint run` hard-fails on v2 (`unsupported version of the configuration: ""`; verified with 2.13.1). CI only works because `golangci-lint-action@v4` + `version: latest` + `install-mode: goinstall` silently resolves to **v1.64.8** (verified in run `36349279578` logs) — so the linter can never upgrade. Also `gosimple`, `linters-settings`, `issues.exclude-rules` are v1-only.

### #38 — CI hardening **[MEDIUM]**
- `ci.yml:11` `permissions: contents: write` at workflow scope (confirmed in the Lint job's token log) so test/lint/build all run with write access; `actions/checkout@v5` leaves the token in `.git/config` (`persist-credentials` unset); actions tag-pinned not SHA-pinned; `version: latest` for golangci and goreleaser. `minesweep.yml` additionally interpolates `${{ github.base_ref }}` into a `run:` shell block and uploads SARIF from a **second full scan** under `continue-on-error`, so a truncated result publishes as if complete.

### Low (12)
- `matchingLineIndex == -1` → off-by-one line numbers (`output.go:214`). Proven unreachable via the engine (`LineIndex.Context` always emits exactly one `"> "`; non-centre lines are `"  "`-prefixed); reachable through the exported `WriteText` — the shape already exists in `output_test.go:104`.
- `censorSecretSubstrings` overlap guards (`sanitize.go:191-205`) are **dead, not harmful** — `FindAllStringIndex` returns disjoint ascending spans, replacements are fixed-length. Delete so nobody "fixes" the loop into left-to-right.
- Trailing/bare `**` never matches — `.minesweepignore` `a/**` leaves `a/b/leak.env` fully scanned (`walker.go:199-204`). Fails open.
- `IgnoreSet.AddNested(".")` unreachable — `strings.Trim(".", "/") == "."`, and `ancestorDirs` never yields `"."`. Harmless via the CLI (root rules already in base via `DiscoverIgnore`); breaks library users of `filesystem.Walk` (`walker.go:397`).
- Scanning a directory named `.git` yields zero files and a clean exit — VCS prune tests `d.Name()` without checking `path == root` (`walker.go:685-690`).
- `GenerateAnnotations` ignores `f.Action`, so a policy-allowed finding is still annotated (`annotations.go:22-44` vs `main.go:622`).
- No range validation on numeric flags: `--min-confidence 5` → silent clean scan. Negative values silently coerced by scattered `<= 0` fallbacks (tested with `=`, since `--flag -3` is rejected by pflag).
- `dangerously_show_secrets` is a valid config key with no `configFields` entry — accepted and silently ignored.
- `developer` profile's `env → allow` is dead for high+ findings (`*` precedes it).
- Missing `--suppress`/`--baseline` paths no-op silently; `--update-baseline` creates the file at the typo'd path.
- `WalkStats.SkippedSymlink` and `IsTextFile`/`IsBinaryFile`/`IsUTF8`/`HasBOM` all dead.
- `.minesweepignore` semantics documented nowhere — `README.md` has zero occurrences; only the `--no-ignore` help string mentions it. Last tag release left the Homebrew tap stale (run `36347398465` 403'd on `homebrew-tap`, so `brew install hxmbl/tap/minesweep` — README's primary install — points at an older version).

### Investigated, NOT reproducible
- Exponential backtracking in `matchGlobParts` (no memoisation is real, but 40 `**` segments vs a 40-deep path completed in **0s**; the `filepath.Match` failure fast-path prunes it). Theoretical only.
- SARIF `startLine == 0` — traced every producer (`LineCol` always ≥1; base64 `remap` clamps; entropy adds +1; filetype/symlink hardcode 1; `attachEvidence` skips `Line <= 0`); only the exported `WriteSARIF` lacks a clamp.
- No data races: `go test -race ./...` passed; a `-race` build found 0 races across default/`--history`/`--staged`/`--diff`/`--include-tests --no-ignore`/`--snippets -v`/`--benchmark`.
- No raw-secret leak in the **primary value** path: checked all 8 output modes for both an AWS secret and a generic password — all clean. (The leak is in *context/snippet* text, #2.)
- `getUserRulesDir` only reads `~/.config/minesweep/rules` — confirmed no gitleaks auto-discovery.

---

## 4. Work already completed

Only two findings were implemented. Everything else is untouched.

### #1 — the literal gate

**Original code** (`detectors/gate.go`, `collectRequired`, `case syntax.OpLiteral`):
```go
case syntax.OpLiteral:
    lit := string(re.Rune)
    if lit == "" { return nil }
    if re.Flags&syntax.FoldCase != 0 {
        return []gateBranch{{gateAlt{alts: []string{strings.ToLower(lit)}, fold: true}}}
    }
    return []gateBranch{{gateAlt{alts: []string{lit}, fold: false}}}
```
The folded gate searches `lowered` = `bytes.ToLower(content)`, ASCII-only.

**Why wrong:** Go's regexp `(?i)` uses Unicode simple folding. I confirmed with a standalone probe that `syntax.Parse("(?i)postgres(?:ql)?://", syntax.Perl)` produces `sub[0] = OpLiteral, FoldCase=true, Rune="POSTGRES"` — so `(?i)postgres` **does** match `poſtgreſ`. The gate needle `postgres` is absent from `bytes.ToLower("poſtgreſ://…")`, so `satisfied` returns false and `safeMatch` returns nil before the regex runs.

**What I changed:** added `asciiFoldLiteral(lit string) (string, bool)` to `gate.go`:
```go
func asciiFoldLiteral(lit string) (string, bool) {
	lower := make([]byte, 0, len(lit))
	for _, r := range lit {
		if r >= utf8.RuneSelf { return "", false }
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f >= utf8.RuneSelf { return "", false }
		}
		if r >= 'A' && r <= 'Z' { r += 'a' - 'A' }
		lower = append(lower, byte(r))
	}
	return string(lower), true
}
```
and in `collectRequired`:
```go
if re.Flags&syntax.FoldCase != 0 {
    // ... comment about bytes.ToLower being ASCII-only ...
    lower, ok := asciiFoldLiteral(lit)
    if !ok { return nil }
    return []gateBranch{{gateAlt{alts: []string{lower}, fold: true}}}
}
```
Changed imports from `(bytes, regexp/syntax, strings)` to `(bytes, regexp/syntax, unicode, unicode/utf8)`. (`strings` became unused after the change — the compiler caught it.)

**Why this fixes the root cause:** the gate is only sound if the needle is guaranteed present in the haystack whenever the regex matches. Since the haystack is ASCII-lowercased, that holds exactly when every rune of the literal folds within ASCII. Returning "no gate" instead of an unsound gate converts a silent false negative into merely a slower scan.

**Tests added** to `detectors/gate_test.go` (plus `bytes`/`strings`-free imports — I added `bytes`):
- `TestGateDropsUnsoundFoldedLiterals` — asserts `asciiFoldLiteral` rejects `secret`, `password`, `aws_secret_access_key`, `key`, `monkey`; accepts `credential`, `auth`, `jwt`, `gcp`, `oauth`, `ARN`, `bearer`, `region`; and lowercases `ARN`→`arn`.
  - *My first draft of this test used `AWS_ACCESS_KEY_ID`, `postgres`, `token`, `AKIA`, `database_url` as "safe" examples — all wrong, each contains k or s. The test caught it.*
- `TestEmbeddedRulesGatesNeverRejectMatchingInput` — loads the real embedded rules via `NewRegexDetector("/nonexistent-rules-dir-for-test")` and asserts, for 5 inputs (long-s password, long-s secret, plain password, uppercase postgres, etc.), that **no** rule whose own `compiled` regex matches the content has a gate that rejects it.
- `TestGateFoldedLiteralCaseNormalization` still passes **unchanged**: `(?i)postgres(?:ql)?://` now degrades to a `://` gate (sound and still useful), because `postgres` is rejected but `://` is fold-safe.

**Verified:**
- `A/.env` (`DB_PASSWORD=…`) → 5 rules: `database-password`, `database_credentials_kv`, `env-password`, `generic-password`, `entropy-high`.
- `B/.env` (`DB_PAſſWORD=…`) → before: `entropy-high` only; after: **same 5 as A**.
- `C/.env` (B + unrelated `# … mentioning secret`) → after: same 5.
- `aws.env` vs `aws_obf.env` (`s`→`U+017F` in the keyword): after fix both → `entropy-high` + `aws-secret-key` (severity 5). Before: obfuscated gave only `entropy-high`.
- Full `go test ./... -count=1` green at that point.

**Caveat I should flag:** this is a pure soundness/speed trade. Rules whose keyword contains `k` or `s` now run their regex on every file. I intended to measure the perf impact with `--benchmark` but **never did**. Expect a slowdown on `env-password`, `env-api-key`, `env-token`, `database-password`, `aws-secret-key`, `azure-client-secret`, and most OAuth/database patterns. If it matters, the next lever is a fold-aware haystack (e.g. also index `unicode.SimpleFold` variants) rather than weakening the gate.

### #8 — credential-shaped identifiers and calibration

Four coordinated changes.

**(1) New file `detectors/value.go`.** Shared judgement of whether a capture is secret material:
```go
const minCredentialValueLen = 8
var attrChain = regexp.MustCompile(`^[A-Za-z_][A-Za-z_]*(?:\.[A-Za-z_][A-Za-z_]*)+$`)

func looksLikeCredentialValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < minCredentialValueLen { return false }
	if isQuotedLiteral(v) { return true }
	if strings.ContainsAny(v, "(){}[]\n\r\t\v\f ") { return false }
	if strings.ContainsAny(v, "<>") { return false }
	if attrChain.MatchString(v) || strings.HasSuffix(v, ".") { return false }
	return true
}

func isQuotedLiteral(v string) bool {
	if len(v) < 2 { return false }
	a, b := v[0], v[len(v)-1]
	return (a == '"' && b == '"') || (a == '\'' && b == '\'') || (a == '`' && b == '`')
}

func assignmentValueLooksLikeCredential(assignment string) bool {
	i := strings.IndexAny(assignment, ":=")
	if i < 0 || i == len(assignment)-1 { return false }
	return looksLikeCredentialValue(assignment[i+1:])
}

func judgeCapturedValue(capture string, hasExplicitGroup bool) bool {
	if hasExplicitGroup { return looksLikeCredentialValue(capture) }
	return assignmentValueLooksLikeCredential(capture)
}
```

**(2) Line-bounded assignment separators.** Mechanically replaced `\s*[:=]\s*` → `[ \t]*[:=][ \t]*` and `\s*[:{"]\s*` → `[ \t]*[:{"][ \t]*` across `rules/aws.yml`, `azure.yml`, `database.yml`, `env.yml`, `gcp.yml`, `generic.yml` (Python pass, 6 files) and `detectors/database.go`, `detectors/oauth.go`. Result: no `\s*[:=]\s*` remains anywhere in `rules/` or `detectors/` (only in a test fixture string and a doc comment). `rules/aws.yml:52`'s `[:{"]` form was fixed by hand afterwards.

**(3) Opt-in `require_value`.** Added `RequireValue bool \`yaml:"require_value,omitempty"\`` to `detectors.Pattern`, checked in `safeMatch`:
```go
if p.RequireValue && !judgeCapturedValue(string(value), g > 0) { continue }
```
Set `require_value: true` on `env-password`, `env-api-key`, `env-token`, `env-private-key-path` (rewrote `rules/env.yml` wholesale with a comment block explaining why), and on `database-password` in `rules/database.yml`. For the Go detector, added `requireValue bool` to `dbPattern`, a `newDBAssignmentPattern` constructor, applied it to `database_credentials_kv`, and in `Detect`:
```go
value := string(data[start:end])
if pattern.requireValue && !assignmentValueLooksLikeCredential(value) { continue }
```
I also changed `env-api-key`'s value class from `[^\s"']+` to `[^\s"']{8,}` so the built-in minimum agrees with the helper.

**(4) Removed the context-free `generic-api-key` rule** from `rules/generic.yml` (`\b([A-Za-z0-9\-_]{40,45})\b` conf 0.10, `\b([0-9a-fA-F]{32})\b` conf 0.15), leaving an explanatory comment block. `generic-api-key-context` already covers the real case with proper assignment context.

**Tests added** — `detectors/value_test.go` (new file):
- `TestLooksLikeCredentialValueRejectsCode` — `state.get(`, `lookup(`, `os.environ[`, `config.`, `${SECRET_`, `self.token`, `process.env.`, `abcdefg`, `""`.
- `TestLooksLikeCredentialValueAcceptsSecrets` — `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `postgres://svc:8fJq2vQzLmNp4Rt@db.internal:5432/app`, `ghp_ABC…`, `Qz7Xm2Pq9Rt4Lv8Nc3Kd6Wj1`, `"hunter2hunter2"`, `'p@ss(w)rd{with}[brackets]'`, a JWT, `~/.ssh/id_rsa`, `8fJq2vQzLmNp4Rt`.
  - *I initially listed `-----BEGIN RSA PRIVATE KEY-----` as accepted; it failed (unquoted values with spaces are rejected) and I removed it after confirming PEM detection is handled by dedicated rules that never reach this check.*
- `TestAssignmentValueLooksLikeCredential` — table incl. `db_password=`, `db_password` (no sign).
- `TestCredentialShapedIdentifiersAreNotFindings` — the exact 11-line `finder.py` from the user's note; asserts **zero** rule findings.
- `TestRealSecretsStillDetected` — asserts `aws-access-key-id`, `aws-secret-key`, `env-password`, `env-api-key`, `env-token`, `database-password`, `generic-password` all still fire.
- `TestAssignmentRulesDoNotConsumeNextLine` — the 3-line `!= token:` loop; asserts no finding captures `"position…"` or contains `\n`.

**Verified end-to-end with `/tmp/ms`:**
- `/tmp/t8/finder.py`: before 8 findings (lines 3, 8, 9, 10, 11×3, 12) → after **NO FINDINGS**.
- `/tmp/t8/real.env`: line 1 `aws-access-key-id`+entropy; line 2 `database_credentials_kv`, `env-password`, `database-password`, `generic-password`; line 3 `env-api-key`, `env-password`, `generic-api-key-context`; line 4 `aws-secret-key`; line 5 `postgres-connection-string` + `postgresql_connection_string`; line 6 `env-token`, `generic-api-key-context`.
- PEM (`-----BEGIN RSA PRIVATE KEY-----`) still → `generic-pem-certificate`, `generic-rsa-private-key`, `ssh-private-key`, `entropy-high`.
- ODBC single-line string still → `sql_connection_string` + others. **Compared against `/tmp/ms-old` (built from a stash) — identical output**, confirming no regression.
- Corpus `$(go env GOMODCACHE)/github.com/spf13`: **75 findings → 32**. Breakdown of the 43 removed: 37 `generic-api-key` (intended) + 6 `env-token`, which I inspected individually: 4× `github-token: ${{secrets.GITHUB_TOKEN}}` (GitHub Actions expression — correctly rejected, it contains `{`/`}`) and 2× viper `README.md:756` `token: 89h3f98hbwf987h3f98wenf89ehf` (a documentation example).

**The bug I introduced and fixed mid-flight (important for review):** the first version of the `require_value` check called `looksLikeCredentialValue(value)` on the raw capture. For rules with **no** `capture_group` (`env-password`, `env-token`, `env-api-key`, `env-private-key-path` all capture group 0 = the *whole assignment*), the capture is `token: 89h3f98hbwf987h3f98wenf89ehf`, which contains a space → **rejected**. I caught it by re-running the spf13 corpus and noticing the 6 `env-token` disappearances, then inspecting each one. Fixed by introducing `judgeCapturedValue(capture, hasExplicitGroup)`; `safeMatch` passes `g > 0` as `hasExplicitGroup`. After the fix, viper's README token is detected by **both** binaries. **This edit came after the last full `go test ./...` run.**

**Unverified / still to measure:** the perf cost of #1's gate narrowing; whether `go test ./...` passes after the `judgeCapturedValue` edit; the spf13 corpus number *after* that edit (I only re-checked the two specific files).

---

## 5. Current working-tree state

**Base:** `main` @ `70291d0`, upstream `origin/main`. Originally clean.

**Uncommitted changes in the working tree.** Nothing committed. No branch created. One `git stash -q` / `git stash pop -q` pair was executed (to build `/tmp/ms-old` from pristine `main` for before/after comparison) and completed, so the changes are in the tree, **not** in a stash. I believe the stash is empty but **could not verify**.

**Modified files:**
- `detectors/gate.go` — added `asciiFoldLiteral`, changed `collectRequired` fold branch, imports now `bytes, regexp/syntax, unicode, unicode/utf8`.
- `detectors/gate_test.go` — added `TestGateDropsUnsoundFoldedLiterals` and `TestEmbeddedRulesGatesNeverRejectMatchingInput`; import block now `bytes, testing, minesweep/filesystem`.
- `detectors/regex.go` — added `RequireValue bool` field to `Pattern` (with doc comment); added the `RequireValue` check in `safeMatch` using `judgeCapturedValue(string(value), g > 0)`; gofmt'd (the `Pattern` struct field alignment changed).
- `detectors/database.go` — added `requireValue bool` to `dbPattern`; added `newDBAssignmentPattern`; `database_credentials_kv` switched to it and its regex line-bounded; `Detect` now computes `value := string(data[start:end])` once and checks `assignmentValueLooksLikeCredential`.
- `detectors/oauth.go` — regexes line-bounded only (no `requireValue`; its value classes already exclude `.`/`(`/`[`).
- `rules/aws.yml`, `rules/azure.yml`, `rules/database.yml`, `rules/gcp.yml`, `rules/generic.yml` — mechanical `\s*[:=]\s*` → `[ \t]*[:=][ \t]*`; `database.yml` also `require_value: true`; `generic.yml` also `generic-api-key` removed with comment block.
- `rules/env.yml` — **fully rewritten** via the write tool (all separators line-bounded, `require_value: true` on the four value-capturing rules, `{8,}` on `env-api-key`, explanatory comment block).

**New files (untracked):** `detectors/value.go`, `detectors/value_test.go`.

**Deleted:** nothing.

**Binaries in `/tmp` (outside the repo):** `/tmp/ms` (current build), `/tmp/ms-old` (build from stashed pristine `main`, used for A/B), `/tmp/ms-race` (race build). Scratch dirs `/tmp/t1`, `/tmp/t8`, `/tmp/t8b`, `/tmp/gp`, `/tmp/msprobe`, `/tmp/ms-verify`, `/tmp/ms-repro`, `/tmp/ms-note*` — some removed, some not; irrelevant to the repo.

**Test status — precise:**
- `go test ./... -count=1` → **all packages ok**, run *before* the `judgeCapturedValue` edit.
- `go test ./detectors/ -count=1` → **ok**, run *after* it (and again after the final `value.go` rewrite).
- `go vet ./...` → clean, run at the very start (before any change).
- `gofmt -l` → clean after each `gofmt -w` on `detectors/`.
- **`golangci-lint run` has NOT been run against my changes.** The repo's v1 config is incompatible with the installed v2.13.1, so this needs either a v1 binary or the config migration (#37).

**What I cannot currently inspect:** the actual `git status` / `git diff`, so I cannot rule out a stray formatting change or an unintended edit in the six rule YAMLs beyond what I described. **The next instance should run `git diff` and read it in full before doing anything else.**

---

## 6. Decisions and reasoning

**Why remove `generic-api-key` rather than retune it.** It was `\b[A-Za-z0-9\-_]{40,45}\b` at confidence 0.10 and `\b[0-9a-fA-F]{32}\b` at 0.15. Neither has discriminating power: they match every long identifier, truncated git SHA, UUID-without-dashes, and content hash. Its own file comment claimed "Only match high-entropy strings that look like API keys" and "requires context" — **neither was implemented**. The honest fix was to implement the documented intent or delete the pattern; deleting was cleaner because the sibling `generic-api-key-context` already performs detection *with* context (`(api[_-]?key|secret[_-]?key|…)[ \t]*[:=][ \t]*['"]?([A-Za-z0-9\-_]{20,})['"]?`). I considered keeping the rule with a higher confidence, but confidence isn't the problem — the pattern is. I considered keeping only the 32-hex pattern, but it matches every md5 in every lockfile and every short git SHA. I removed the whole rule and left a comment explaining the removal and that `--rules` can restore it. **Trade-off accepted:** a secret that exists *only* as a bare 32-hex or bare 40-char token with no assignment context is no longer reported by default. I judged that acceptable because such a value is indistinguishable from a hash, and users who want it can re-add it.

**How `require_value` is meant to work.** It is deliberately **opt-in per pattern**, because not every rule captures a value: `env-generic-credential` is `(?mi)^(SECRET|PASSWORD|TOKEN|KEY|CREDENTIALS|SIGNING_KEY)=` — a canary whose whole point is to flag a credential-named variable with *nothing* after it. A blanket filter would silently delete that rule. So each pattern declares its own contract. I added it only to rules that genuinely capture a value: `env-password`, `env-api-key`, `env-token`, `env-private-key-path`, `database-password` (YAML) and `database_credentials_kv` (Go). Rules whose value class already excludes `.`/`(`/`[`/`{` (the OAuth patterns, `generic-api-key-context`, `generic-password` — well, `generic-password`'s class is `[A-Za-z0-9@#$%^&+=]{8,}` which permits `os.environ`, so it *did* get `require_value`) don't strictly need it but I added it where the class was permissive.

**How captured values are judged — the subtlety.** A rule either names a `capture_group` (then the capture *is* the value) or captures group 0 (then the capture is the whole assignment and only the part after the first `:`/`=` is the value). `judgeCapturedValue(capture, hasExplicitGroup)` dispatches on `g > 0`. **This was my own bug** — the first version judged the raw capture uniformly and rejected `token: 89h3f…` because group 0 contains a space. Caught by corpus inspection, not by the unit tests, which is a lesson: my `TestRealSecretsStillDetected` didn't include a no-`capture_group` rule whose value had no surrounding context, so it passed while real detection regressed.

**Why assignment matching became line-bounded.** `\s*` between a credential name, the sign, and the value includes `\n`, so `haystack[i] != token:` at end of line matched the first 8+ characters of the *next* line. The finding was then reported at a line whose `source_line` contained no value at all, and the actual captured text was in the context but not the source line — three defects from one cause. `[ \t]*` makes the separator horizontal-only. I applied it mechanically to every occurrence in `rules/` and `detectors/` rather than patching individual rules, because the bug class is uniform and a partial fix would leave the same false negative reachable. I did **not** change the `\s*` in `sql_connection_string`'s `data\s*source` (multi-word literal) or in `env-generic-credential`'s `(?mi)^…=`, which are not assignment separators.

**Why the Unicode gate must stay sound rather than "usually right."** The gate is a *precondition*: if it says "this pattern cannot match here" and that is wrong, the pattern is skipped and there is no recovery — the finding simply does not exist, and no downstream filter or report can reveal that. So the rule I applied is: emit a gate only when it is provably implied by the regex. For folded literals that provability requires the ASCII-fold assumption to hold, which `asciiFoldLiteral` checks per rune via the full `unicode.SimpleFold` cycle. I considered building a fold-aware haystack (e.g. also searching the ASCII variants of non-ASCII orbit members) and rejected it as disproportionate for the two offending letters; I considered dropping fold gates entirely and rejected it as too costly. Alternatives considered and rejected: `bytes.ToLower` → `strings.ToLower` (still doesn't fold ſ, which is already lowercase); restricting gates to literals with no letters at all (too weak).

**Semantics I believe are right for the remaining bugs** (see §7 for mechanics):
- **Censoring** should key off the set of secrets the engine *knows about* for a file, not a heuristic over evidence text. A heuristic over printed text is unfixable in principle: the same characters mean "secret" in one place and "identifier" in another.
- **Coverage gaps** must never be able to produce a clean-looking exit. A skipped file is a finding about the scan, not an absence of findings. This argues for routing *every* skip reason — including VCS prunes, symlink escapes and unreadable directories — into one accounting path, and for `Incomplete` when a coverage gap is material.
- **Trust boundary:** anything that reduces coverage or adds suppression must be `secure: true`. "Performance" and "coverage" are not the same axis, and the original classification conflated them.
- **Symlinks:** the guard must validate what the kernel will actually open (fully resolved), not a lexical approximation of it. And an unsafe/broken/escaping link must be a *coverage gap*, not a silent empty file counted as scanned.
- **Determinism:** any truncation that decides *which* findings survive must run on a deterministic order. Sorting after truncation is too late.
- **Baselines** must record what was reported, post-filter and post-trim.
- **Terminal output** must be sanitised at every print site, including git-controlled and filename-controlled strings, and `SanitizeTerminal` should escape C1 and strip `\n`/`\t` where a single line is required.

---

## 7. What I was about to do

### #2 (secret leakage) — the immediate next step

**Root cause I intended to attack:** the censoring layer tries to guess "is this token a secret?" from the printed text using a heuristic (`looksLikeSecret`'s unique-character ratio) that is calibrated for high-alphabet random strings, so it fails in exactly the cases that matter most (hex, base32, low-entropy-but-real credentials) and fragments credentials at punctuation (`secretCandidate`'s narrow class). The engine, meanwhile, **already knows** every secret value it found in a file — that knowledge is simply not threaded into rendering.

**Files I expected to change:**
1. `engine/engine.go` — in `detect()`, collect every raw captured `Value` for the file (before confidence/severity/tag filtering, so even low-confidence hits are known) and attach them to the surviving findings, e.g. a package-level side channel or a new field on the evidence step. Because `detect` is per-file and single-goroutine, a plain `[]string` local plus a new `attachEvidence(file, filtered, fileSecrets)` signature is sufficient and race-free; no mutex needed.
2. `report/sanitize.go` — the substantive work:
   - `CensorFinding` gains the file's secret set and censors **all** of them out of `SourceLine`/`Context`, not just `f.Value`.
   - Restructure so `isCensoredToken(f.Value)` only suppresses re-censoring of the `Value` field itself, never the evidence (fixes 2e).
   - Widen `secretCandidate` to cover all printable non-space characters so a credential is never split into fragments (fixes 2b). Risk to manage: widening the class increases false censoring of ordinary code in context lines, which hurts readability of a report meant to be pasted into an LLM.
   - Replace the `uniqueChars/len > 0.6` test with something that does not reject low-alphabet secrets. My sketch: keep `len >= 8` and `>= 2 character classes`, then accept if `shannonEntropy >= 3.0` **or** the token is hex-like (≥16 chars, all `[0-9a-fA-F]`) **or** `uniqueRatio > 0.6`. This catches hex and base32 while still ignoring prose and identifiers.
   - Also censor a whitespace-normalised form of the value (`strings.Join(strings.Fields(v), " ")`) so a multi-line capture still matches against `LineIndex.Context`'s per-line `TrimSpace` output (fixes 2d).
3. `report/output.go:222,242` — stop re-hashing an already-hashed token: when `isCensoredToken(f.Value)`, run only `censorSecretSubstrings` and skip `CensorValue` (fixes 2f).
4. Related, if time allows: `findings/severity.go:102` `RedactValue` returning a constant (#25), so all redact-action findings share one token.

**Tests I intended to write** (in `report/sanitize_test.go` or a new file):
- Adversarial: a `.env` with an AWS key on line 1 and a 32-hex `SIGNING_HASH` on line 2 → assert the rendered text contains neither `d41d8cd98f00b204e9800998ecf8427e` nor its 64-hex cousin, in **both** default and `-v` and `--snippets` modes. This is the exact shape that leaked.
- Adversarial: `admin_password=P@ssw0rd$ecret!2024` adjacent to a finding → assert `ssw0rd$ecret` does not appear (the prefix-tokenisation bug).
- Property-ish: for a set of synthetic secrets (hex 32, hex 64, base32, punctuation-heavy, quoted-with-brackets, JWT, URL-with-creds), each must be absent from every rendered line of a report that mentions it.
- `CensorFinding` must still censor evidence when `f.Value` is already `sha256:<12hex>` (bug 2e).
- `--snippets` token consistency: the token in a snippet must equal the token in the `Value:` line (bug 2f).
- Multi-line capture: a SQL connection-string finding whose `Context` is rendered must not print the password (bug 2d).
- Non-regression: the primary `Value` path must still be hashed in all modes; `SanitizeTerminal` behaviour unchanged.

**Edge cases I was thinking about:** over-censoring making reports unreadable (the reason to prefer the file-secret-set over blanket regexing); a secret that appears in a *different* file than the one it was found in (out of scope — the set is per-file); the base64 detector, whose findings are remapped onto the parent file's line index; history mode, where `SourceLine`/`Context` come from a blob; short values where `ReplaceAll` would mangle ordinary text (e.g. a 2-char capture replacing every occurrence) — probably worth a minimum-length guard before censoring by exact match.

### Then how I intended to proceed

Group by shared root cause rather than by number:
- **Finding-budget + coverage accounting** (#3, #7, #32): one structural change — a shared thread-safe budget, and one accounting path for every skip reason. Also close #33's `HasPrefix(rel, "..")` while I'm in `walker.go`.
- **Symlinks** (#5, #6): resolve the scan root; validate the fully resolved target; surface unsafe/broken/escaping links as coverage gaps. Also add the missing `SkipReasonSymlink` accounting (#32).
- **Ignore files** (#9, #10): per-directory `IgnorePattern` bases; narrow `isTestFile`.
- **Trust + config** (#4, #13, #20, #23, #31): reclassify coverage keys as secure; resolve rules/policy dirs against the scan target; auto-discover `.gitleaks.toml` **rules only** (allowlists only when explicitly trusted) with a loud warning; accept a single file for `--rules`.
- **Determinism + baselines** (#11, #12): sort before trim; write the baseline after trim and suppression.
- **Output hygiene** (#14, #24–#29, #35, #36): sanitise every print site, escape C1, fix the double-hash, fix `HighlightSyntax` gating, fix the redact token, stop `--benchmark` writing the baseline.
- **Small correctness** (#15–#19, #21, #30, #33, #34): each small and independent.
- **CI/packaging** (#37, #38, plus the stale tap).

---

## 8. Things I am uncertain about

- **I could not inspect the working tree.** No `git status`, no `git diff`. The six rule YAMLs were edited by a scripted string replacement; I only read back `env.yml` (which I rewrote wholesale) and `database.yml`/`generic.yml` excerpts. **`aws.yml`, `azure.yml`, `gcp.yml` I have not re-read since the rewrite.** Please read the full diff.
- **The full test suite has not been run since the `judgeCapturedValue` edit.** `./detectors/` is green. Everything else is unverified after that change.
- **`golangci-lint` has not been run at all** against my changes. `revive`/`gosimple` could complain about e.g. the new `asciiFoldLiteral`.
- **Perf impact of #1 is unmeasured.** Dropping folded gates for any literal containing `k` or `s` affects a lot of rules. This could be a significant slowdown and I have no numbers.
- **`TestEmbeddedRulesGatesNeverRejectMatchingInput` passes vacuously for rules whose gate is nil** (it `continue`s). It proves soundness for gated rules and, by the fact that the obfuscated inputs match, implicitly that the regexes do match — but it does not assert that any particular rule still fires. The stronger check is the end-to-end binary comparison, which I did by hand.
- **Whether #8 weakened any real detection on a broader corpus.** I only compared `github.com/spf13`. The user's own visync comparison and the 15 planted credentials were never re-run against my build — I don't have that repo. The 15-credential list from the note (AWS, GitHub, Stripe, Slack, npm, JWT, RSA/SSH, postgres+mongo URIs, passwords) is exactly the regression suite I should have re-run.
- **#10's fix direction is a judgement call.** Narrowing `*.test.*` detection by extension preserves `prod.test.tfvars` but means a real `secret.test.ts` would still be skipped. There is no way to distinguish those from the name alone; my proposal (only treat `.test`/`.spec` as a marker for known test-source extensions) is a heuristic. Worth confirming with the user.
- **#9's fix is a real refactor** of `IgnoreSet`. I have not designed it beyond "per-directory base, evaluate relative to its own directory, shallowest-first, last match wins". Nested-vs-ancestor precedence currently works (subagent verified: deeper negation correctly re-includes) and must not regress.
- **The subagent audits' unverified claims.** I verified B1 (ignore flattening), B3a (symlink chain), B6 (test files), B7 (trailing `**`) myself. I did **not** verify: symlink loops leaving `symlinkState` unmarked; `os.Stat` on a symlink-to-directory producing a wrong `Size`; `writeRiskFactors`' unsanitised output (I verified a neighbouring field, `report.Reasons`, myself); `WriteGitHubWorkflowSummary` / `WriteAnnotationsToFile` being dead in the CLI; `sarif.go` rule descriptors being unsanitised; `censorSecretSubstrings` guards being dead (analysis only); dashboard per-rule severity inconsistency; `annotations.go` comma escaping; UTF-8 rune splitting in `val[:60]` / `msg[:57]` / `ruleID[:15]`.
- **Whether the `.gitleaks.toml` auto-discovery design (#20) will satisfy the user.** My plan was rules-only-from-repo for trust reasons, which means a migrating user's existing allowlist still won't apply automatically. That is a deliberate deviation from the user's note's expectation and should be flagged to them explicitly.
- **Duplicate rule IDs (#21) last-wins vs first-wins.** I chose last-wins so `10-base` / `20-override` filename ordering expresses precedence, consistent with `fs.ReadDir` returning sorted names. Not confirmed with the user.
- **`DefaultConfidenceFloor = 0.05`** interacts with user-authored rule confidences (#30). I did not change it. A custom rule with `confidence: 0.05` or lower is silently off. Worth a decision.
- **I never measured whether the two subagents' "unreachable"/"dead code" conclusions hold in the current tree** — some of that code may already have been touched by my edits (e.g. `walker.go` was not edited; `detectors/database.go` and `oauth.go` were).

---

## 9. Recommended continuation order

1. **`git status` and read the full `git diff`.** Then `go build ./... && go test ./... -count=1`. Confirm the tree is where §5 says it is before building on it. If `judgeCapturedValue` broke anything else, fix that first.
2. **Re-run the user's own regression material against the current build**: the 15 planted credentials from the note, and if `visync` is available, a before/after finding count. This is the acceptance test for #8 and I never got to run it. Do this before touching anything else, so there's a known-good baseline for the rest of the work.
3. **Finish #8's verification**: re-run the spf13 corpus A/B (`/tmp/ms-old` may still exist, or rebuild from `git stash`), confirm the number, and confirm `viper`'s README token still fires. Then measure `--benchmark` before/after to quantify #1's cost, and if the cost is material, look at a fold-aware haystack rather than relaxing the gate.
4. **#2** as planned in §7. It is the highest-severity remaining item and shares its blast radius with #24/#25/#26, so do those print-layer fixes in the same pass.
5. **#3 + #7 + #32 + #33** as one unit (budget + coverage accounting + the `..` prefix), since they all live in `engine.go`/`walker.go` and share the "a file that was not inspected must be visible" principle.
6. **#5 + #6** together (symlinks), also in `filesystem/`.
7. **#9 + #10** (ignore semantics + test-file heuristics) in `walker.go`.
8. **#4 + #13 + #20 + #23 + #31** (trust boundary + config resolution + gitleaks discovery). Flag the rules-only-from-repo decision to the user.
9. **#11 + #12** (determinism, baseline).
10. **#15–#19, #21, #30, #34** (small independent correctness).
11. **#22–#29, #35, #36** (output/CI-adjacent), then **#37 + #38** (CI permissions, golangci schema, action pinning), and the stale Homebrew tap.

Rationale: 1–3 because everything after depends on a trustworthy tree and a verified #8; 4–7 next because they are the remaining detection-integrity and coverage-silent-failure bugs and they cluster in two files; 8–10 after that; the rest are cheap and independent.

---

## 10. Anything else

- **The `tools` object is a proxy that returns a stub function for *any* key.** `typeof tools.shell` returns `"function"`. The failure only appears on invocation with `Unknown tool 'shell'`. If the next instance (or the user) probes tool availability, a `typeof` check will lie. Use an actual call in a try/catch.
- **Tool surface changed mid-session**: originally `shell`, `read`, `edit`, `write`, `glob`, `grep` plus `execute`/`subagent`; later only `execute` wrapping browser/opencode/t3-code. I had used two background `subagent` calls (`explore`) for the ignore-file and report-layer audits — that mechanism may not be available.
- **Two background audits I commissioned** (ignore-file semantics; report/output layer) produced the findings I marked `[REPORTED]`. Their session IDs were `ses_efce53810ffexHo6a2VlIG9r8n` (report layer) and `ses_efce5380effedXDc1wsROvgtmG` (ignore layer).
- **`go build -o /tmp/ms ./cmd/minesweep` is the build command**; tests are `go test ./... -count=1`; race is `go test -race ./... -count=1`.
- **The repo scans itself poorly on purpose.** `.msignore` ignores `rules/`, `README.md`, `detectors/database.go`, `git/git.go`, `*_test.go`, `minesweep`, `dist/`. So `minesweep .` in the repo will not flag the example patterns in the rule files. Don't mistake that for a regression.
- **`github.com/spf13` in the module cache is a good calibration corpus** (`viper`, `cobra`, `pflag` — real code, plenty of assignment-shaped identifiers and CI workflow files). Beware it contains several versions of the same module.
- **macOS `/tmp` → `/private/tmp` symlink is load-bearing for #15.** Reproduce with `cd /tmp/...` in a shell whose `$PWD` is the unresolved path, then `--diff`/`--staged`.
- **The 0.05 confidence floor and `ActionAllow` for `low`** mean `entropy-high` findings never affect exit codes — that is intentional, but it is also why the user's "gate is green" observation was partly about which *severity band* things land in, not only about false positives. Re-measure `--min-severity medium` **after** the #8 fix rather than trusting the pre-fix number.
- **README drift to consider updating if you touch these areas:** the `generic-api-key` rule removal, the gitleaks auto-discovery behaviour (#20), the `.golangci.yml` v1 schema, and the "benchmark runs always exit 0" claim (#29).


---
Thank you for everything. 
\- User


You're welcome. A few closing notes:

**On the handoff** — the two things I'd most want the next instance to do first are both cheap: `git diff` in full (I edited six rule YAMLs by scripted string replacement and only read back two of them), and `go test ./... -count=1` (green one step *before* the last `judgeCapturedValue` edit).

**The thing I'd flag as most likely to bite** — #8 has two acceptance tests I never got to run against my own build: your 15 planted credentials, and the visync before/after count. I verified the fix against synthetic fixtures and the spf13 corpus, and I did catch (and fix) one regression mid-flight where `require_value` wrongly rejected viper's README token. But "credential-shaped identifiers are no longer findings" and "no real secret is still missed" are only half-proven until those two run. If the 15/15 holds, #8 is genuinely done. If any dropped, the `require_value` opt-in list in `rules/env.yml` and `rules/database.yml` is where to look first.

**On the perf trade in #1** — I fixed it for soundness and did not measure the cost. Dropping folded gates for any literal containing `k` or `s` affects a lot of rules. Worth a `--benchmark` comparison before shipping; if it's material, the fix is a fold-aware haystack rather than relaxing the gate.

**One open question that's yours to settle** — #20. I concluded `.gitleaks.toml`'s `[allowlist]` *does* work when the file is loaded (I tested it; the original note was wrong on that point), and that the real defect is that nothing auto-discovers the file. My planned fix contributes **rules only** from an auto-discovered repo-local `.gitleaks.toml`, honouring allowlists only when explicitly passed via `--rules`, because an untrusted allowlist is a repo weakening its own scan — same class as the `max_file_size_mb` trust hole. That means a migrating user still won't get their existing allowlist applied automatically. Deliberate, but it's a deviation from what you expected, so it should be your call rather than mine.

Nothing is committed. The changes are in the working tree, not a stash.
\- Agent
