package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
)

const (
	tokenPrefix = "sha256:"
	tokenLength = 12
)

// SecretToken returns a stable, non-reversible identifier for value.
// Equal values always produce equal tokens; the original cannot be recovered
// from the token.
//
// The token is a hash rather than a truncated prefix. A prefix such as
// "AKIA1234.." is still a partial credential: it narrows a brute force, it
// identifies the secret to anyone holding a candidate list, and for short
// values the "prefix" is most of the secret. A hash leaks nothing, is identical
// for the same secret everywhere it appears, and therefore still lets findings
// be correlated across files, runs and baselines.
func SecretToken(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return tokenPrefix + hex.EncodeToString(sum[:])[:tokenLength]
}

// IsCensoredToken reports whether s is already a censorship token, so censoring
// is not applied twice and tokens survive round-tripping.
func IsCensoredToken(s string) bool {
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

// secretNeedle returns the part of a captured value that is actually the secret.
//
// Many rules capture group 0, which for an assignment rule is the whole
// "password=P@ssw0rd$ecret!2024" rather than just the value. Replacing that
// string verbatim inside the source line also destroys the key name, so a line
// came out as "admin_sha256:5fcea9cfa5ab" instead of "admin_password=sha256:...".
func secretNeedle(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] != '=' && v[i] != ':' {
			continue
		}
		left := v[:i]
		if len(left) < 2 || !identifierSide.MatchString(left) {
			continue
		}
		right := trimDelimiters(v[i+1:])
		// "postgres://host/db" has an identifier-shaped scheme in front of a
		// colon, but the whole URL is the captured value.
		if right == "" || strings.HasPrefix(right, "//") {
			continue
		}
		return right
	}
	return v
}

// CensorValue replaces every occurrence of a known secret in text with its
// token.
//
// A value that spans several lines is censored line by line, because the
// evidence it is matched against is built one trimmed line at a time and a
// single whole-value ReplaceAll cannot line up with it. An already-censored
// value is left alone: hashing a token is how the same secret ended up printed
// under two different identifiers in one report.
func CensorValue(text, value string) string {
	if text == "" || value == "" || IsCensoredToken(value) {
		return text
	}
	token := SecretToken(value)
	needle := secretNeedle(value)
	if !strings.ContainsAny(value, "\n\r") {
		return strings.ReplaceAll(text, needle, token)
	}
	for _, piece := range strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' }) {
		piece = strings.TrimSpace(piece)
		if len(piece) < minCensorExactLen {
			continue
		}
		text = strings.ReplaceAll(text, piece, token)
	}
	return text
}

// minCensorExactLen is the shortest value censored by exact match. Below this a
// replacement would fire on unrelated text that happens to contain the same few
// characters, mangling the line without protecting anything: a two-character
// "secret" matches everywhere.
const minCensorExactLen = 4

// CensorEvidence censors secrets out of a piece of printed evidence.
//
// knownSecrets are values the engine positively identified in the same file, so
// they are censored by exact match without any guessing. Anything else secret
// shaped is caught by the heuristic pass, which exists because the engine cannot
// know about a credential that no rule matched — a bare 32-hex signing hash
// beside a real key is not a finding, but it is printed in the snippet.
//
// An already-censored token in knownSecrets or in value carries no information
// about the original text and must not be re-hashed: that produced two different
// tokens for the same secret in the same report.
func CensorEvidence(text string, knownSecrets []string) string {
	if text == "" {
		return text
	}
	for _, secret := range knownSecrets {
		if secret == "" || IsCensoredToken(secret) {
			continue
		}
		text = CensorValue(text, secret)
	}
	return censorSecretShaped(text)
}

// candidateRun matches a maximal run of non-whitespace characters. Taking the
// whole run and splitting it at the assignment sign is what keeps a credential
// in one piece: the previous character class omitted "@ $ % ^ & * + ! ~ ?", so
// "P@ssw0rd$ecret!2024" was split and the tail after the fragment that passed
// the entropy test was printed verbatim.
var candidateRun = regexp.MustCompile(`[^\s]+`)

// identifierSide matches the key half of an assignment: "SIGNING_HASH",
// "admin_password", "aws_secret_access_key". Used to find where the value starts
// so that the key name is never itself treated as a candidate.
var identifierSide = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// delimiterChars are stripped from the edges of a candidate. They are
// structural in source text — quotes, brackets, statement punctuation — so a
// run of them can never be part of a credential, while a run that merely
// contains one (a password with an '@') must be kept whole.
const delimiterChars = "\"'`(){}[]<>,;|"

func trimDelimiters(s string) string {
	return strings.Trim(s, delimiterChars)
}

// valueOf returns the part of a whitespace-free run that could hold a secret:
// everything after the first assignment sign, or the whole run when there is no
// sign. Without this split, "SIGNING_HASH=d41d8cd98f00b204e9800998ecf8427e" was
// one candidate and the key name was hashed along with the value, leaving the
// snippet unreadable.
//
// A sign only splits when the text before it is a plausible identifier, so a URL
// like "postgres://svc:pw@host" keeps its scheme.
func valueOf(run string) string {
	for i := 0; i < len(run); i++ {
		if run[i] != '=' && run[i] != ':' {
			continue
		}
		left := run[:i]
		if len(left) >= 2 && identifierSide.MatchString(left) {
			return trimDelimiters(run[i+1:])
		}
	}
	return trimDelimiters(run)
}

// codePath matches an ordinary dotted identifier chain such as os.environ or
// config.database.url. Such a chain has enough distinct characters to look
// random, and censoring it would bury the report in noise without protecting
// anything: a real secret is never spelled this way.
var codePath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// censoredMarker is what replaced text used to be filled with. It is kept so
// that re-censoring an already-censored report is a no-op.
const censoredMarker = "[CENSORED]"

// containsCensoredToken reports whether s already holds a rendered token, even
// with something in front of it. The digest is 12 hex characters and therefore
// itself scores above the entropy threshold, so without this a line whose value
// had just been tokenised was censored a second time.
func containsCensoredToken(s string) bool {
	i := strings.Index(s, tokenPrefix)
	if i < 0 {
		return false
	}
	rest := s[i+len(tokenPrefix):]
	if len(rest) < tokenLength {
		return false
	}
	return IsCensoredToken(tokenPrefix + rest[:tokenLength])
}

// censorSecretShaped censors tokens that look like credential material even
// though nothing identified them precisely.
//
// The judgement is deliberately biased towards censoring. Snippet output is
// meant to be pasted into a ticket or an LLM, so a missed credential is a real
// disclosure while a redacted identifier only costs readability.
func censorSecretShaped(line string) string {
	matches := candidateRun.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
		return line
	}

	type candidate struct {
		start int
		end   int
		value string
	}

	candidates := make([]candidate, 0, len(matches))
	for _, match := range matches {
		run := line[match[0]:match[1]]
		// Check the whole run as well as the value: valueOf splits at the first
		// assignment sign, so for an already-censored "sha256:78314b11be2e" the
		// value part is "78314b11be2e", which is itself high-entropy and would be
		// hashed a second time.
		if IsCensoredToken(run) || containsCensoredToken(run) {
			continue
		}
		value := valueOf(run)
		if value == "" {
			continue
		}
		// Offsets are relative to the trimmed value, not to the run.
		offset := strings.Index(run, value)
		if IsCensoredToken(value) || strings.Contains(value, censoredMarker) || !looksLikeSecret(value) {
			continue
		}
		candidates = append(candidates, candidate{
			start: match[0] + offset,
			end:   match[0] + offset + len(value),
			value: value,
		})
	}

	if len(candidates) == 0 {
		return line
	}

	// Replace right-to-left so that replacing one candidate cannot shift the
	// offsets of another. FindAllStringIndex returns disjoint ascending spans
	// and valueOf only shrinks a span, so no two candidates can overlap.
	result := line
	for i := len(candidates) - 1; i >= 0; i-- {
		c := candidates[i]
		if c.end > len(result) || result[c.start:c.end] != c.value {
			continue
		}
		result = result[:c.start] + SecretToken(c.value) + result[c.end:]
	}
	return result
}

const minSecretLen = 8

// hasTwoClasses reports whether s mixes at least two character classes: a single
// class is prose or a run of repeated letters, which never carries a credential.
func hasTwoClasses(letter, digit, other bool) bool {
	return (letter && digit) || (other && (letter || digit))
}

// looksLikeSecret decides whether a token has the shape of credential material.
//
// It must not repeat the mistake it replaces: the previous test was a unique
// character ratio above 0.6, which a 32-hex secret cannot reach no matter how
// random it is, because hex has only 16 symbols (ratio 0.375 at length 32,
// 0.25 at length 64). Every long hex or base32 credential was therefore printed
// in full. Entropy per character, plus the two alphabet-restricted alphabets
// that real keys use, are tested instead.
func looksLikeSecret(s string) bool {
	if len(s) < minSecretLen || codePath.MatchString(s) {
		return false
	}

	var hasLetter, hasDigit, hasOther bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasOther = true
		}
	}

	// At least two character classes: a single class is prose or a run of
	// repeated letters, which never carries a credential.
	if !hasTwoClasses(hasLetter, hasDigit, hasOther) {
		return false
	}

	// Keys are generated from an alphabet of at least 16 symbols encoding 64 or
	// more bits, so a real credential of this length essentially always contains
	// a digit. Requiring one is what separates "aws_secret_access_key" from a
	// secret: without it, any dotted or underscored identifier long enough to
	// clear the entropy threshold was reported as a credential, which made the
	// snippet output useless.
	if isHexAlphabet(s) && len(s) >= 16 {
		return true
	}
	if isBase32Alphabet(s) && len(s) >= 16 {
		return true
	}
	if !hasDigit {
		return false
	}
	if shannonEntropyBits(s) >= 3.0 {
		return true
	}
	// Fall back to the unique-character ratio for the short, high-alphabet
	// tokens that entropy alone rates below the threshold.
	return uniqueRatio(s) > 0.6
}

func isHexAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func isBase32Alphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// shannonEntropyBits returns the per-character entropy of s in bits.
func shannonEntropyBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func uniqueRatio(s string) float64 {
	var seen [256]bool
	unique := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			unique++
		}
	}
	return float64(unique) / float64(len(s))
}
