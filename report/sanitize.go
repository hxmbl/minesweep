package report

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"minesweep/findings"
)

// SanitizeTerminal neutralizes terminal control sequences embedded in
// attacker-influenced strings (file paths, secret values, context lines,
// git author names, commit summaries). Escape sequence injection can set
// window titles, clear screens, or overlay fake UI while a user reads
// a scan report.
//
// ESC is rendered visibly as \e; other C0 controls except \n and \t are
// rendered in caret notation. C1 controls (U+0080–U+009F) are neutralised too:
// they are the 8-bit aliases of CSI, OSC, DCS and friends, and several
// terminals honour them directly. Previously only ESC was caught, because a
// literal ESC in the string is what triggers needsEscape, and U+009B alone
// passed through untouched.
//
// Newlines and tabs are preserved, because this function is also applied to
// genuinely multi-line text (a finding's context block) whose layout depends on
// them. For single-line attacker-controlled fields use SanitizeTerminalInline,
// which neutralises those too — a newline in a filename or commit summary is a
// report-forging primitive, since it can start a line that looks like a
// legitimate part of the report.
func SanitizeTerminal(s string) string {
	if !strings.ContainsFunc(s, needsEscape) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch r {
		case 0x1b:
			b.WriteString(`\e`)
		case 0x7f:
			b.WriteString("^?")
		case 0x85:
			b.WriteString("[NEL]")
		case 0x9b:
			b.WriteString("[CSI]")
		case 0x9d:
			b.WriteString("[OSC]")
		default:
			switch {
			case r >= 0x90 && r <= 0x9f:
				b.WriteString("[C1]")
			case r < 0x20 && r != '\n' && r != '\t':
				b.WriteByte('^')
				b.WriteByte(uint8(r) + '@') //nolint:gosec // guarded by r < 0x20
			default:
				b.WriteRune(r)
			}
		}
	}

	return b.String()
}

// SanitizeTerminalInline is SanitizeTerminal for text that occupies exactly one
// line of a report: file paths, git author names, commit summaries, rule names
// and descriptions, skipped-path labels, dashboard fields.
//
// A newline in any of those is not layout, it is an injection: it lets the
// value start a line that reads as part of the report, so a skipped file named
// "x.png\nINCOMPLETE SCAN - 0 files scanned" would otherwise print a forged
// verdict inside a clean scan.
func SanitizeTerminalInline(s string) string {
	if !strings.ContainsFunc(s, needsEscape) && !strings.ContainsAny(s, "\n\t") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return SanitizeTerminal(b.String())
}

func needsEscape(r rune) bool {
	return (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f ||
		(r >= 0x80 && r <= 0x9f)
}

// CensorValue replaces every occurrence of a sensitive value in a source
// line with a stable, non-reversible token.
//
// The token is a hash rather than a truncated prefix. A prefix such as
// "AKIA1234.." is still a partial credential: it narrows a brute force, it
// identifies the secret to anyone holding a candidate list, and for short
// values the "prefix" is most of the secret. A hash leaks nothing, is
// identical for the same secret everywhere it appears, and therefore still
// lets findings be correlated across files, runs, and baselines.
func CensorValue(line, value string) string {
	if line == "" || value == "" {
		return line
	}
	return strings.ReplaceAll(line, value, SecretToken(value))
}

// SecretToken returns a stable, non-reversible identifier for value.
// Equal values always produce equal tokens; the original cannot be recovered
// from the token.
func SecretToken(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return tokenPrefix + hex.EncodeToString(sum[:])[:tokenLength]
}

const (
	tokenPrefix = "sha256:"
	tokenLength = 12
	// minSecretFragmentLen is the shortest fragment the heuristic will censor
	// on its own. It is below the 8-byte looksLikeSecret floor so that the two
	// tests stay independent, and short enough that splitting an assignment on
	// "=" does not strand a credential in a fragment too small to judge.
	minSecretFragmentLen = 4
	// hexSecretMinLen is the length at which an all-hex run is treated as a
	// digest or hex-encoded credential. It sits well above the length of a
	// colour literal, offset or short hash fragment, and well below the 32
	// characters of an MD5 digest, which is the shortest form in common use.
	hexSecretMinLen = 20
	// shortPathSegmentMax is the longest segment still considered part of a
	// path rather than of a secret when a candidate contains a slash.
	shortPathSegmentMax = 7
)

// isCensoredToken reports whether s is already a censorship token, so
// censoring is not applied twice and tokens survive round-tripping.
func isCensoredToken(s string) bool {
	if !strings.HasPrefix(s, tokenPrefix) {
		return false
	}
	digest := s[len(tokenPrefix):]
	if len(digest) != tokenLength {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// secretTokenRe matches a censorship token anywhere inside a larger string.
//
// A token is 19 bytes of [a-z0-9:] , all of which secretCandidate accepts, so
// once one has been substituted into a line it glues onto the identifier in
// front of it (`admin_sha256:1d31bdafd1e9`) and the heuristic pass censors the
// combination. That re-hashed the token, so the same secret showed two
// different identifiers in one report and the "equal values produce equal
// tokens" correlation that baselines depend on was destroyed. A candidate that
// already contains a token is left alone.
var secretTokenRe = regexp.MustCompile(tokenPrefix + `[0-9a-f]{` + strconv.Itoa(tokenLength) + `}`)

func containsCensoredToken(s string) bool {
	return secretTokenRe.MatchString(s)
}

// CensorFinding returns a copy of f with the secret value replaced by its
// token everywhere it appears: in the value itself, the reported source line,
// and the surrounding context block.
//
// Every path through this function censors the evidence. An earlier version
// returned early when f.Value was empty or already a token, on the assumption
// that there was nothing to hide — but Context and SourceLine are raw file
// content regardless of whether this particular finding carries a value, and
// the file-type and symlink detectors emit findings with no Value at all.
// That is how a SQLite database's first "line" reached every report format
// verbatim.
func CensorFinding(f findings.Finding) findings.Finding {
	value := f.Value
	if isCensoredToken(value) {
		// Already tokenized. Re-running the exact replacement would hash the
		// token a second time, so the same secret would show two different
		// identifiers in the same report. Only the heuristic pass applies.
		f.SourceLine = censorSecretSubstrings(f.SourceLine)
		f.Context = censorSecretSubstrings(f.Context)
		return f
	}
	token := SecretToken(value)
	f.SourceLine = censorAllValues(f.SourceLine, value)
	f.Context = censorAllValues(f.Context, value)
	f.Value = token
	return f
}

// CensorReport returns a copy of rep with every finding censored. Reports are
// censored once, at the output boundary, so no output format can be the one
// that forgets.
func CensorReport(rep *findings.RiskReport) *findings.RiskReport {
	if rep == nil {
		return nil
	}
	out := *rep
	if len(rep.Findings) > 0 {
		out.Findings = make([]findings.Finding, len(rep.Findings))
		for i, f := range rep.Findings {
			out.Findings[i] = CensorFinding(f)
		}
	}
	return &out
}

// censorAllValues censors the primary finding value and other values that
// strongly resemble credentials or secrets. It is intentionally conservative
// about what it considers secret-like: snippets are opt-in, but ordinary code
// should still remain readable.
func censorAllValues(line, primaryValue string) string {
	if line == "" {
		return line
	}
	// A primaryValue that is already a token means the exact-replacement
	// step has run on this line before. Running it again would censor the
	// token itself into a different token, which is how --snippets came to
	// show two different hashes for one secret.
	if isCensoredToken(primaryValue) {
		return censorSecretSubstrings(line)
	}
	result := CensorValue(line, primaryValue)
	return censorSecretSubstrings(result)
}

// secretCandidate matches a contiguous credential-like token.
//
// The character class is deliberately broad. A narrower one fragments the
// credential and censors only the fragment it happened to cover: with
// `[A-Za-z0-9_.:/=-]` a password containing several kinds of punctuation was
// cut at the first character not in the class, so `sha256:…` replaced only the
// leading fragment and the remainder printed verbatim. A partial redaction is a
// leaked redaction, which is why the class is broad enough to cover the
// punctuation that actually appears in passwords.
//
// The class still excludes brackets, quotes, parentheses, commas, whitespace
// and semicolons, so ordinary code structure, paths with many segments and
// prose stay separable.
var secretCandidate = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_.:/=+~$%^&*!?@#-]{6,}[A-Za-z0-9]`)

// span is a byte range of the line that should be replaced by a token.
type span struct {
	start int
	end   int
	value string
}

// censorSecretSubstrings finds and censors secret-like tokens without treating
// an entire URL/path as a secret merely because it contains punctuation.
//
// A candidate that is an assignment is split at the "=" and each side judged
// separately. Judging the whole run conflated the identifier with its value:
// a cloud key assignment is one candidate whose unique-character ratio sits
// just under the threshold, so the key survived while the identifier beside it
// did not.
//
// "=" is the only split point. Splitting on ":" or "/" as well seemed tidier
// but destroyed the very signal being measured — a secret with no digits, such
// as `wJalrXUtnFEMI`, is recognisable only because the surrounding run carries
// separators, and `arrow-left-24px` inside a file path became a "secret" once
// it was isolated from its neighbours.
func censorSecretSubstrings(line string) string {
	matches := secretCandidate.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
		return line
	}

	var spans []span
	for _, match := range matches {
		// Guard at the candidate level, not per span: splitting
		// `sha256:066b98cdb9f6` at the colon yields the digest on its own,
		// which is short and hex-shaped enough to look secret-like and would
		// be tokenized, producing `sha256:sha256:…`.
		candidate := line[match[0]:match[1]]
		if isCensoredToken(candidate) || containsCensoredToken(candidate) ||
			strings.Contains(candidate, "[CENSORED]") {
			continue
		}
		spans = append(spans, censorableSpans(line, match[0], match[1])...)
	}

	if len(spans) == 0 {
		return line
	}

	// Replacing right-to-left keeps the offsets of earlier spans valid: a
	// replacement is longer than the text it replaces, so it would otherwise
	// shift everything after it.
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })

	result := line
	applied := 0
	for _, s := range spans {
		if s.end > len(result) {
			continue
		}
		// Skip a span whose text no longer matches, i.e. one an earlier
		// (overlapping) replacement already changed.
		if result[s.start:s.end] != s.value {
			continue
		}
		result = result[:s.start] + SecretToken(s.value) + result[s.end:]
		applied++
	}
	if applied == 0 {
		return line
	}
	return result
}

// censorableSpans returns the sub-ranges of line[start:end] that should be
// tokenized.
func censorableSpans(line string, start, end int) []span {
	whole := line[start:end]
	if whole == "" {
		return nil
	}
	// No separator: the whole run is one opaque token, judged as such. The
	// decision must not be taken here when separators are present — the
	// combined run of an identifier and its value is judged as neither.
	if !strings.ContainsAny(whole, spanSeparators) {
		if secretish(whole) {
			return []span{{start: start, end: end, value: whole}}
		}
		return nil
	}

	var out []span
	offset := start
	for offset < end {
		rel := strings.IndexAny(line[offset:end], spanSeparators)
		if rel < 0 {
			if part := line[offset:end]; secretish(part) {
				out = append(out, span{offset, end, part})
			}
			break
		}
		part := line[offset : offset+rel]
		if secretish(part) {
			out = append(out, span{offset, offset + rel, part})
		}
		offset += rel + 1 // skip the separator itself
	}
	return out
}

// spanSeparators split a candidate into an identifier part and a value part.
const spanSeparators = "="

// secretish reports whether a fragment is worth censoring on its own.
func secretish(v string) bool {
	if len(v) < minSecretFragmentLen {
		return false
	}
	if isCensoredToken(v) || containsCensoredToken(v) || strings.Contains(v, "[CENSORED]") {
		return false
	}
	return looksLikeSecret(v)
}

// looksLikeSecret determines whether a string has characteristics commonly
// associated with credentials or other high-entropy secret material.
func looksLikeSecret(s string) bool {
	if len(s) < 8 {
		return false
	}

	// A URL query fragment is structure, not a credential. Widening the
	// candidate alphabet to include "?" and "&" was necessary so a password
	// containing them would not be censored only in part, but it also made
	// `settings?page=2&sort=name` a single candidate. A credential that
	// contains "?" is overwhelmingly a URL in the first place.
	if strings.ContainsAny(s, "?#") {
		return false
	}

	// A run of short slash-separated segments is a module or directory path.
	// `github.com/spf13/cobra` is six letters and two digits — dense enough to
	// clear every entropy heuristic — and censoring it made module paths in
	// evidence lines unreadable. A real secret with separators has at least
	// one segment long enough to carry the entropy.
	if looksLikeShortPath(s) {
		return false
	}

	hasLetters := false
	hasDigits := false
	hasSpecial := false

	for _, c := range s {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetters = true
		case c >= '0' && c <= '9':
			hasDigits = true
		case strings.ContainsRune("_-. /=:+~$%^&*!?@#", c):
			hasSpecial = true
		}
	}

	// A candidate should contain at least two different character classes.
	mixCount := 0
	if hasLetters {
		mixCount++
	}
	if hasDigits {
		mixCount++
	}
	if hasSpecial {
		mixCount++
	}

	if mixCount < 2 {
		return false
	}

	// A long hex run is a digest or a hex-encoded credential. The
	// unique-character ratio deliberately used below cannot catch these: a
	// 32-character hex secret has at most 16 distinct symbols, a ratio of
	// 0.5, so it failed every threshold and printed verbatim. Recognising the
	// alphabet directly is both more accurate and far narrower than lowering
	// the ratio, which would have censored ordinary identifiers such as
	// `ISO8601DateTimeFormatter`.
	if len(s) >= hexSecretMinLen && isHexAlphabet(s) {
		return true
	}

	// A dotted or underscored run whose every segment is purely alphabetic is
	// a source identifier — `logger.Info`, `process.env`, `tenant_id`,
	// `AWS_SECRET_ACCESS_KEY` — not an opaque token. Censoring those made
	// evidence lines unreadable without protecting anything: the secret is
	// the value on the right-hand side, which carries no separators and is
	// therefore judged on its own. This is why `admin_password` stays
	// readable while the password next to it is tokenized.
	if looksLikeIdentifier(s) {
		return false
	}

	// Otherwise approximate randomness with a unique-character ratio. This is
	// deliberately not called "entropy": it is only a heuristic.
	uniqueChars := make(map[rune]struct{}, len(s))
	for _, c := range s {
		uniqueChars[c] = struct{}{}
	}

	ratio := float64(len(uniqueChars)) / float64(len([]rune(s)))
	return ratio > 0.6
}

// looksLikeShortPath reports whether s looks like a module or directory path:
// it contains a slash and every segment is short. Segments are delimited by
// both "/" and "." so that the host part of a module path (`github.com`) does
// not read as one long opaque segment. This is the shape that distinguishes
// `github.com/spf13/cobra` from a joined secret such as
// `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, whose segments are long enough to
// carry entropy on their own.
func looksLikeShortPath(s string) bool {
	if !strings.Contains(s, "/") {
		return false
	}
	segments := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '.' })
	if len(segments) < 2 {
		return false
	}
	for _, seg := range segments {
		if seg == "" || len(seg) > shortPathSegmentMax {
			return false
		}
	}
	return true
}

// looksLikeIdentifier reports whether s is a dotted or underscored source
// identifier: it must be separated, and every segment must be purely
// alphabetic. Anything carrying a digit, a slash, an at-sign or mixed
// punctuation in a segment is left to the other tests.
func looksLikeIdentifier(s string) bool {
	if !strings.ContainsAny(s, "._") {
		return false
	}
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '_' }) {
		if seg == "" || len(seg) > 32 {
			return false
		}
		for _, c := range seg {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
				return false
			}
		}
	}
	return true
}

// isHexAlphabet reports whether every byte is a hex digit.
func isHexAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// HighlightSyntax applies basic syntax highlighting to a code line based on
// common patterns. It returns a string with ANSI color codes for different
// token types.
//
// This is intentionally lightweight rather than a full language parser.
func HighlightSyntax(line, fileType string) string {
	if line == "" {
		return line
	}

	var result strings.Builder
	i := 0

keywordLoop:
	for i < len(line) {
		// Skip whitespace.
		if line[i] == ' ' || line[i] == '\t' {
			result.WriteByte(line[i])
			i++
			continue
		}

		// Check for comments.
		if i+1 < len(line) && line[i:i+2] == "//" {
			result.WriteString("\033[36m")
			result.WriteString(line[i:])
			result.WriteString("\033[0m")
			break
		}

		// Check for shell-style comments.
		if line[i] == '#' {
			result.WriteString("\033[36m")
			result.WriteString(line[i:])
			result.WriteString("\033[0m")
			break
		}

		// Check for strings.
		if line[i] == '"' || line[i] == '\'' {
			quote := line[i]

			result.WriteString("\033[33m")
			result.WriteByte(quote)
			i++

			for i < len(line) && line[i] != quote {
				if line[i] == '\\' && i+1 < len(line) {
					result.WriteByte(line[i])
					i++
					result.WriteByte(line[i])
					i++
					continue
				}

				result.WriteByte(line[i])
				i++
			}

			if i < len(line) {
				result.WriteByte(quote)
				i++
			}

			result.WriteString("\033[0m")
			continue
		}

		// Check for common keywords.
		remaining := line[i:]
		keywords := []string{
			"export",
			"const",
			"var",
			"func",
			"if",
			"else",
			"return",
			"import",
			"package",
			"true",
			"false",
			"nil",
		}

		for _, kw := range keywords {
			if strings.HasPrefix(remaining, kw) {
				if len(remaining) == len(kw) || !isWordChar(remaining[len(kw)]) {
					result.WriteString("\033[35m")
					result.WriteString(kw)
					result.WriteString("\033[0m")
					i += len(kw)
					continue keywordLoop
				}
			}
		}

		result.WriteByte(line[i])
		i++
	}

	return result.String()

}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}
