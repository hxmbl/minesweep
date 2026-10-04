package detectors

import (
	"regexp"
	"strings"
)

// minCredentialValueLen is the shortest run of characters that can plausibly be
// a credential. Shorter captures are variable references or punctuation.
const minCredentialValueLen = 8

// attrChain matches a dotted sequence of letters and underscores, which is how
// an attribute access reads in source (`process.env`, `config.settings.auth`).
// Digits are excluded from segments so that structured tokens whose segments
// happen to be alphanumeric — JWTs above all — are not mistaken for code.
var attrChain = regexp.MustCompile(`^[A-Za-z_][A-Za-z_]*(?:\.[A-Za-z_][A-Za-z_]*)+$`)

// looksLikeCredentialValue reports whether a regex capture looks like secret
// material rather than the source code that produced it.
//
// Assignment rules such as `(?i)(token)[ \t]*[:=][ \t]*([^\s"']{8,})` capture
// whatever follows the sign. In real code that is frequently an expression
// rather than a literal:
//
//	token = state.get("token")             -> "state.get("
//	api_key = lookup("api_key")            -> "lookup("
//	password = os.environ["DB_PASSWORD"]   -> "os.environ["
//	password = process.env.DB_PASSWORD     -> "process.env.DB_PASSWORD"
//	key = ${SECRET_FROM_VAULT}             -> "${SECRET_FROM_VAULT}"
//	token = <your-token-here>              -> "<your-token-here>"
//
// None of those is a credential, and reporting them teaches users to ignore
// the scanner. The shapes above are unambiguous, so rejecting them costs no
// real coverage: a genuine secret is a quoted literal or a single opaque token.
//
// Anything the author quoted is taken at face value, because a real password
// may contain any punctuation at all, including every character rejected below.
// Multi-word unquoted values are rejected for the same reason: they are prose,
// not a token. PEM blocks and connection strings, which legitimately contain
// spaces and semicolons, are matched by dedicated rules that never reach here.
func looksLikeCredentialValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < minCredentialValueLen {
		return false
	}
	if isQuotedLiteral(v) {
		return true
	}
	// Brackets, braces, parentheses, or any whitespace: we captured an
	// expression, a container, or a multi-token phrase.
	if strings.ContainsAny(v, "(){}[]\n\r\t\v\f ") {
		return false
	}
	// Angle brackets mark a placeholder, a heredoc, or a shell redirect.
	if strings.ContainsAny(v, "<>") {
		return false
	}
	// An attribute chain is code, not a credential. A trailing dot is the
	// truncated form of one ("process.env.").
	if attrChain.MatchString(v) || strings.HasSuffix(v, ".") {
		return false
	}
	// The value is an opaque token of the right shape. The last question is
	// whether it claims to be a real one, and checked-in placeholders answer
	// that in their own text: `changeme`, `REPLACE_ME`, `your-token-here`,
	// `xxxxxxxx`, `sha256:9f86…`. See example.go for why the bar is narrow.
	if LooksLikeExample(v) {
		return false
	}
	return true
}

func isQuotedLiteral(v string) bool {
	if len(v) < 2 {
		return false
	}
	a, b := v[0], v[len(v)-1]
	return (a == '"' && b == '"') || (a == '\'' && b == '\'') || (a == '`' && b == '`')
}

// assignmentValueLooksLikeCredential judges a capture that spans a whole
// assignment — an identifier, a separator, and a value — rather than just the
// value. The value is whatever follows the first sign; the identifier in front
// of it is the whole point of the match and must not be mistaken for the
// secret.
func assignmentValueLooksLikeCredential(assignment string) bool {
	_, ok := credentialValue(assignment)
	return ok
}

// credentialValue narrows a capture that spans a whole assignment to the part
// after the first sign, and reports whether that part looks like a credential.
//
// It exists because judging the value and reporting the match are different
// decisions, and conflating them corrupts the report. A rule with no capture
// group — which is every one of the four env-* rules, the highest-volume rules
// in the set — matched
//
//	secret = "whsec_8fKd93Ml20Xq7Zb1Rt6"
//
// and reported Value as the entire string, identifier and quotes included.
// Three consequences, all observed in one scan of one README:
//
//   - CensorValue replaced the whole assignment with one token, so the evidence
//     line rendered as `sha256:426d3e6d6ff6` — the context that makes a finding
//     reviewable was gone.
//   - The same secret produced a different token per rule: env-password
//     hashed `secret = "whsec_…"`, entropy-high hashed `whsec_…`, env-api-key
//     hashed `APP_SECRET="whsec_…"`. That breaks the documented promise that
//     equal values produce equal tokens, which is what lets findings be
//     correlated across files, runs and baselines.
//   - An allowlist entry written against the real secret did not match,
//     because the value being matched was the assignment.
//
// So: judge the value, and report the value. The byte offsets stay on the whole
// match, because a finding should point at the assignment the user recognises,
// not at a substring of it.
func credentialValue(assignment string) (string, bool) {
	i := strings.IndexAny(assignment, ":=")
	if i < 0 || i == len(assignment)-1 {
		// No sign, or nothing after it: there is no value to judge.
		return "", false
	}
	// Peel the quotes the pattern's own `["']?` left behind.
	//
	// They arrive asymmetrically. `(?i)(password|…)[ 	]*[:=][ 	]*["']?[^\s"']{8,}`
	// consumes an opening quote but can never consume the closing one, because
	// the value character class excludes it. The captured value was therefore
	// `"whsec_8fKd93Ml20Xq7Zb1Rt6` — a leading quote and no trailing one.
	//
	// That asymmetry is not cosmetic. A value with a stray quote fails
	// isQuotedLiteral, so it took the unquoted path through the shape checks;
	// it failed looksLikePinnedDigest, so every `sha256:` digest was reported;
	// and it was reported verbatim, so the censoring pass replaced
	// `"whsec_8fKd93Ml20Xq7Zb1Rt6` in the evidence line and left the line
	// reading `WEBHOOK_SIGNING_sha256:1d31bdafd1e9"`.
	value := trimValueQuotes(assignment[i+1:])
	return value, looksLikeCredentialValue(value)
}

// trimValueQuotes removes one matching pair of quotes, and otherwise removes
// any unbalanced quote left at either end. An assignment may legitimately
// quote a value in a way the pattern could not balance, and a dangling quote
// would corrupt both the reported value and the redacted evidence line.
func trimValueQuotes(v string) string {
	v = strings.TrimSpace(v)
	if isQuotedLiteral(v) {
		return v[1 : len(v)-1]
	}
	return strings.Trim(v, "\"'`")
}

// judgeCapturedValue applies the value check to a regex capture. A rule that
// names no capture group captures the whole assignment — identifier, sign and
// value — so only the part after the sign is the value. A rule that does name a
// group has already isolated the value.
func judgeCapturedValue(capture string, hasExplicitGroup bool) bool {
	if hasExplicitGroup {
		return looksLikeCredentialValue(capture)
	}
	return assignmentValueLooksLikeCredential(capture)
}
