# Gitleaks TOML compatibility

This document describes MineSweep's compatibility with Gitleaks TOML configuration (`gitleaks.toml`) as imported by `LoadGitleaksRules` / `--rules <file.toml>`.

> Status: **partial compatibility**. MineSweep does **not** claim full behavioral parity with upstream Gitleaks. Unsupported or lossy fields that may affect detection or suppression must produce diagnostics and must not silently weaken policy.

## Pinned reference

- Target schema behavior: Gitleaks v8 configuration concepts (rules, allowlists, `regexTarget`, `path`, `secretGroup`, `entropy`, `keywords`, `tags`, extend/useDefault, commits, composite/required rules). Exact upstream parity requires validation against a pinned Gitleaks release and fixture suite.
- MineSweep implementation: `detectors/gitleaks.go`.

## Compatibility matrix

| Field / feature | Status | MineSweep behavior | Security note |
|---|---|---|---|
| `title` | supported (metadata) | Parsed, not behaviorally used | No detection impact |
| `[[rules]]` | partial | Rules with supported regex patterns are imported as native regex rules | Unsupported rule semantics are warned/skipped |
| `rules.id` | supported | Required; missing IDs skipped with warning | - |
| `rules.description` | supported | Mapped to rule name/description | - |
| `rules.regex` | supported (core) | Compiled as regex pattern | Invalid regex skipped with warning |
| `rules.path` | partial | Rule-level path regex compiled and enforced against file path/relative path | Unsupported/invalid path causes rule skip with warning |
| `rules.secretGroup` | supported | Mapped to capture group | - |
| `rules.entropy` | supported | Mapped to minimum entropy filter | - |
| `rules.keywords` | unsupported (enforced) / lossy | Parsed by schema presence; MineSweep emits warning that keywords are not enforced as preconditions | Not a suppression; may increase matches vs keyword-gated Gitleaks rules (not weaker coverage) |
| `rules.tags` | supported | Appended with `imported-gitleaks` provenance tags | - |
| `rules.allowlist` / `rules.allowlists` | partial | Path/content/stopword/condition/regexTarget handled as independent blocks (any matching block suppresses; AND/OR per block) | Commit allowlists unsupported (warned); semantics should be validated with fixtures |
| `rules.required` / composite required rules | unsupported | Detected and rule skipped with warning to avoid silent semantic drift | **Fail-closed behavior** for this construct |
| `[allowlist]` / `[[allowlists]]` (global) | partial | Compiled and attached as independent blocks; path/content/stopword/condition/regexTarget supported; commits warned unsupported | Commit exclusions not enforced |
| `allowlist.paths` | partial | Compiled as regexes and matched against file path in suppression checks | Must be behavior-tested against upstream expectations |
| `allowlist.regexes` | partial | Compiled and matched against secret value or line depending on `regexTarget` | See regexTarget |
| `allowlist.stopwords` | partial | Case-insensitive substring match against secret value | Semantics may differ from upstream edge cases; needs fixture coverage |
| `allowlist.condition` (`AND`/`OR`) | supported (intended) | Per-block condition honored; empty categories ignored | Covered by unit tests; expand fixtures for parity |
| `allowlist.regexTarget` (`secret`/`line`/`match`) | partial | `secret` and `line` supported; `match` accepted as match-value target (treated as captured value target) with compatibility note/warning path as needed; unknown values warn and default to secret | `match` parity needs behavioral fixtures vs upstream |
| `allowlist.commits` | unsupported | Warning emitted; not enforced | **Can weaken policy if source relied on commit allowlists**; use baseline/suppressions alternatives and review diagnostics |
| `[extend]` / `extend.useDefault` / `extend.path` | unsupported | Warning emitted; external/default extension not loaded | **May weaken policy** if source depends on extended rules; import must be reviewed |
| Rule severity | derived (lossy) | MineSweep assigns severity heuristically from rule ID/description patterns | Not source-of-truth parity |

## Security invariants

- A Gitleaks import must not silently produce materially weaker coverage or broader exclusions than the source policy.
- Unsupported constructs that can exclude findings or change match semantics (e.g. commit allowlists, extends, required/composite conditions) must produce actionable diagnostics. Where safe parity cannot be guaranteed, MineSweep should fail closed (skip affected rule/construct) rather than silently misapply it.
- Every compatibility claim in this matrix should be backed by behavioral tests.

## Known gaps / follow-up

- Add pinned upstream Gitleaks fixture corpus and golden behavioral comparisons.
- Verify `regexTarget = "match"` against upstream for grouped captures and full-match cases.
- Model/port commit allowlists and config extension safely, or hard-fail with prominent diagnostics when present in security-relevant contexts.
- Complete support for composite/required rules or keep fail-closed with explicit reporting.
- Document all warnings in CLI output and machine-readable diagnostics.
