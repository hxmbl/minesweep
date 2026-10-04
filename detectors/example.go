package detectors

import (
	"regexp"
	"strings"
)

// This file answers one question about a captured value: does the value assert
// that it is not a real secret?
//
// The distinction matters because the alternative — reporting it — is what
// makes a gate get removed. A `.env.example` holding
// `DB_PASSWORD=changeme` produced three findings (database credentials, generic
// password, env-password), `API_KEY=changeme` produced a MEDIUM, and a
// README fence holding `webhook_secret = "whsec_..."` produced a HIGH. Seven
// lines of obviously-fake configuration produced fourteen findings. Each one
// is individually defensible; together they are a reason to run
// `git commit --no-verify`, which is the bypass the config rules exist to make
// unnecessary.
//
// The bar for suppression is deliberately narrow, and it is a claim about the
// *whole* value rather than a keyword search inside it:
//
//   - `your-api-key-here`, `REPLACE_ME`, `xxxxxxxx`, `<token>` — the value is
//     self-describing. Nothing real looks like this.
//   - `sha256:9f86…` — a content address. The prefix is an assertion by the
//     author that this is a digest of something, not a bearer credential.
//
// What is NOT suppressed, and why:
//
//   - `password=secret`, `password=admin`, `password=default`. These are
//     dictionary words, and a scanner that stays silent about `password=admin`
//     is not doing its job. A weak real password is still a real password.
//   - Anything merely *containing* "example". `ghp_example…` could be a
//     placeholder or an attacker's padding, and the difference is not knowable
//     from the token. The vendor-prefixed case below is the narrow exception,
//     because there the prefix fixes the alphabet and therefore the length.
//
// The consequence of a wrong call here is a false negative, so every rule here
// is one whose false-negative surface is empty by construction.

// placeholderWords are values that are placeholders by assertion. Each entry
// is matched against the entire value, case-insensitively, after the value has
// been unwrapped from quotes.
//
// Note what is absent: `secret`, `password`, `admin`, `default`, `guest`,
// `test`. Those are real (if poor) passwords. Only values that claim not to be
// credentials belong here.
var placeholderWords = map[string]bool{
	"changeme":          true,
	"change_me":         true,
	"change-me":         true,
	"placeholder":       true,
	"replace_me":        true,
	"replaceme":         true,
	"replace-me":        true,
	"replacethis":       true,
	"insert_value":      true,
	"insert_value_here": true,
	"fill_me_in":        true,
	"fill_me":           true,
	"fillme":            true,
	"dummy":             true,
	"fake":              true,
	"fakevalue":         true,
	"fake_value":        true,
	"notreal":           true,
	"not_real":          true,
	"notarealsecret":    true,
	"not_a_real_secret": true,
	"redacted":          true,
	"example":           true,
	"examplevalue":      true,
	"example_value":     true,
	"sample":            true,
	"todo":              true,
	"fixme":             true,
	"unset":             true,
	"undefined":         true,
	"empty":             true,
	"nothinghere":       true,
	"yourtokenhere":     true,
}

// yourXHere matches the single most common placeholder shape in checked-in
// configuration: `your-token-here`, `YOUR_API_KEY_HERE`, `yourPasswordHere`.
// The middle word is the credential name, so the pattern spans it.
//
// The trailing `here` must be a whole segment, which is what the optional
// separator before it is for. Without it the pattern accepted `your-api-key-there`
// — the string ends in the four letters `here` — so a value that starts with
// "your" and is otherwise opaque was treated as a placeholder. It looked like a
// harmless superset and was a false negative: the shape being matched is
// `your <name> here`, and anything else is a value.
var yourXHere = regexp.MustCompile(`(?i)^your[-_ .][a-z0-9]+(?:[-_ .][a-z0-9]+)*[-_ .]here$`)

// yourXHereCamel matches the camelCase spelling of the same shape:
// `yourPasswordHere`, `yourApiKeyHere`. The capital H is what distinguishes the
// placeholder from a real token, and requiring it keeps the match from extending
// to lowercase runs.
var yourXHereCamel = regexp.MustCompile(`^your[A-Z][A-Za-z0-9]*Here$`)

// placeholderWordRe catches a single word prefixed or suffixed by a
// placeholder marker, as in `password_REPLACE_ME` or `token-CHANGEME`. It
// requires the marker, so `redacted_user_count=4` cannot match on "redacted".
var placeholderWordRe = regexp.MustCompile(`(?i)^(?:[a-z0-9]*[-_ .])?(?:change|replace|insert|fill)[-_ .]?(?:me|this|it|value)?(?:[-_ .][a-z0-9]+)*$`)

// markerSegments are the words that begin a value and declare it to be an
// example. Matching is on the first segment only, so `dummy-value-not-real` and
// `placeholder-token` are recognised while `password` and `secret` are not —
// and a real password that merely ends in `-not-real` is still a password.
//
// `test` is deliberately absent. It is far too common as a real value.
var markerSegments = map[string]bool{
	"changeme": true, "change": true, "replace": true, "replaceme": true,
	"placeholder": true, "example": true, "dummy": true, "fake": true,
	"sample": true, "notreal": true, "notarealsecret": true, "insert": true,
	"fill": true, "redacted": true, "todo": true, "fixme": true, "xxx": true,
}

// startsWithMarkerSegment reports whether v's first segment is a placeholder
// marker.
func startsWithMarkerSegment(v string) bool {
	first := v
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '-', '_', '.', ' ', ':', '/':
			first = v[:i]
		}
		if first != v {
			break
		}
	}
	return markerSegments[strings.ToLower(first)]
}

// digestAlgoHex matches an algorithm-prefixed content digest. `sha256:` before
// hex is a pinned digest — an integrity reference, not a bearer token. No
// provider issues credentials in this shape, which is what makes the
// exclusion sound rather than a heuristic.
var digestAlgoHex = regexp.MustCompile(`(?i)^(?:sha(?:1|224|256|384|512)|md5|blake2[bs]?|sha3|digest|checksum|hash)[-:=](?:[0-9a-f]{32,})$`)

// imageDigest matches the OCI/Docker pinned-image form `@sha256:…`, which is a
// content address of a tarball rather than anything secret.
var imageDigest = regexp.MustCompile(`(?i)@sha(?:256|512):[0-9a-f]{32,}$`)

// vendorExampleToken matches a vendor-shaped token whose body announces itself
// as an example. This is deliberately restricted to tokens with a known
// vendor prefix: the prefix fixes the alphabet, so a real credential of that
// shape cannot contain a run of filler like `xxxxxxxx` or the word `example`
// without becoming invalid for the provider. A generic "contains example"
// rule would be trivially defeated by padding an attacker-chosen key.
var vendorExampleToken = regexp.MustCompile(
	`(?i)^(?:gh[pousr]_[a-z0-9]{20,}|xox[abprs]-[0-9a-z-]{10,}|sk_(?:live|test)_[0-9a-z]{8,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|glpat-[0-9A-Za-z_-]{16,})$`)

// vendorExampleBody matches filler inside a vendor-shaped token body: a run of
// x, or the literal words example/dummy/placeholder/test.
var vendorExampleBody = regexp.MustCompile(`(?i)(?:x{4,}|example|dummy|placeholder|yourkey|notreal|changeme|testkey|faketest)`)

// documentedExamples are credential values published verbatim in vendor
// documentation. They match in full only. These strings are the canonical
// teaching examples for their products, so they appear in tutorials, in blog
// posts, and — as in this repository's own engine test fixture — in the very
// files a scanner is pointed at.
//
// Matching them exactly is what keeps this sound: the strings are fixed and
// public, so treating them as non-secrets cannot hide a different credential.
// A prefix or substring match would, and is not used.
//
// Only genuinely-published values belong here. An invented stand-in buys
// nothing and costs a maintenance obligation, so this list is deliberately
// short: the AWS pair below, and nothing else. Vendor-shaped tokens whose body
// is filler are handled structurally by vendorExampleToken instead, which does
// not require knowing any particular example.
var documentedExamples = map[string]bool{
	// AWS's long-standing documentation pair. Verified by
	// TestDocumentedExamplesAreLowercasedExactly.
	"akiaiosfodnn7example":                     true,
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey": true,
}

// LooksLikeExample reports whether value is, on its own terms, an example
// rather than a credential.
//
// It is consulted after the shape checks in looksLikeCredentialValue, which
// have already established that the value is a bare opaque token. At that
// point the remaining question is not "is this the right shape for a secret"
// but "is this the right shape for a secret that exists", and the value
// frequently answers that itself.
func LooksLikeExample(value string) bool {
	v := unwrapValue(value)
	if v == "" {
		return true
	}
	if looksLikePinnedDigest(v) {
		return true
	}
	// Exact matches first: they are the cheapest and the least ambiguous.
	if documentedExamples[strings.ToLower(v)] {
		return true
	}
	if placeholderWords[normalizePlaceholder(v)] {
		return true
	}
	if yourXHere.MatchString(v) || yourXHereCamel.MatchString(v) {
		return true
	}
	if looksLikeMaskedRun(v) {
		return true
	}
	if placeholderWordRe.MatchString(v) {
		return true
	}
	if startsWithMarkerSegment(v) {
		return true
	}
	// A body of filler inside a vendor-shaped token. The prefix and suffix
	// are both anchored, so this cannot degrade into "contains a word".
	if vendorExampleToken.MatchString(v) && vendorExampleBody.MatchString(v) {
		return true
	}
	return false
}

// unwrapValue removes one layer of matching quotes and the punctuation that
// routinely trails a captured value: a YAML list dash, a trailing comma, a
// closing bracket from a call, or a sentence period inside a comment.
//
// This is not a general trimmer. It peels a fixed, small set of decorations so
// that `token: "changeme"` and `token: "changeme",` are judged the same, and
// stops as soon as the value looks like content.
func unwrapValue(v string) string {
	v = strings.TrimSpace(v)
	for i := 0; i < 2; i++ { // quotes may nest once: `"'changeme'"` is a thing
		if len(v) >= 2 {
			a, b := v[0], v[len(v)-1]
			if (a == '"' && b == '"') || (a == '\'' && b == '\'') || (a == '`' && b == '`') {
				v = v[1 : len(v)-1]
				v = strings.TrimSpace(v)
				continue
			}
		}
		break
	}
	return strings.TrimRight(v, ",;)]}>.")
}

// normalizePlaceholder folds a placeholder to the comparison form used by
// placeholderWords: lowercase with separators removed.
func normalizePlaceholder(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range strings.ToLower(v) {
		if r == '-' || r == '_' || r == ' ' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// looksLikeMaskedRun reports whether v is a filler character repeated to
// redact a value rather than a value at all: `xxxx`, `xxxxxxxx`,
// `00000000`, `********`. It also accepts the grouped form used to preserve a
// value's shape, `xxxx-xxxx-xxxx-xxxx` and `****-****`.
//
// It is written by hand rather than as a regular expression because RE2 has no
// backreferences, and every other alternative — enumerating fillers, or
// comparing a string to its own rotation — is either unbounded or slower.
//
// The threshold is four repeats. Three is short enough that a real short
// credential could plausibly be `aaa`, and a two- or three-character value is
// not worth scanning for anyway; anything shorter has already failed the
// minimum-credential-length check upstream.
func looksLikeMaskedRun(v string) bool {
	if len(v) < 4 {
		return false
	}
	filler := v[0]
	if !isFiller(filler) {
		return false
	}
	// Grouped form: `xxxx-xxxx-xxxx-xxxx`. Every group must be the same
	// filler, at least three long, and separated by exactly one separator.
	if strings.ContainsRune("-_.", rune(filler)) {
		return false
	}
	group, groups := 0, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == filler:
			group++
		case (c == '-' || c == '_' || c == '.') && group >= 3:
			group, groups = 0, groups+1
		default:
			return false
		}
	}
	groups++
	if groups == 1 {
		return group >= 4
	}
	// A grouped run is a mask only if every group is a real group. Trailing
	// or doubled separators leave a group below the minimum.
	return group >= 3
}

// isFiller reports whether c is one of the characters conventionally used to
// mask a value: x, the digits, and the usual asterisk/dot/underscore masks.
func isFiller(c byte) bool {
	switch c {
	case 'x', 'X', '*', '.', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	}
	return false
}

// looksLikePinnedDigest reports whether value is an algorithm-prefixed content
// address or a pinned-image digest.
//
// The reviewer's third finding was three `sha256:`-prefixed values reported at
// 60–70% confidence by the env-token, env-password and env-private-key-path
// rules. Those rules are correct about the grammar — `token = <64 hex>` really
// is credential-shaped — and wrong about the world: `sha256:` is the author
// declaring what the value is. Recognizing it costs the shape rules nothing,
// because the prefix is not something a credential can carry.
//
// Note that `sha256:` is also this tool's own censorship token prefix, so this
// predicate is deliberately the mirror image of looksLikeSecret's token check:
// a line already censored by CensorValue is not re-judged here.
func looksLikePinnedDigest(v string) bool {
	return digestAlgoHex.MatchString(v) || imageDigest.MatchString(v)
}
