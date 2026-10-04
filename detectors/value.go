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
	i := strings.IndexAny(assignment, ":=")
	if i < 0 || i == len(assignment)-1 {
		// No sign, or nothing after it: there is no value to judge.
		return false
	}
	return looksLikeCredentialValue(assignment[i+1:])
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
