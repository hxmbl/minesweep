package findings

import (
	"strings"
	"testing"
)

func TestSecretTokenIsStableAndDistinct(t *testing.T) {
	const a = "AKIAIOSFODNN7EXAMPLE"
	const b = "AKIAIOSFODNN7EXAMPLF"
	if SecretToken(a) != SecretToken(a) {
		t.Error("token for the same value must be stable")
	}
	if SecretToken(a) == SecretToken(b) {
		t.Error("two different values share a token")
	}
	if !IsCensoredToken(SecretToken(a)) {
		t.Error("SecretToken output must be recognised as a token")
	}
	if IsCensoredToken(a) {
		t.Error("a raw value must not be mistaken for a token")
	}
	if SecretToken("") != "" {
		t.Error("empty value has no token")
	}
}

func TestIsCensoredTokenRejectsNearMisses(t *testing.T) {
	if !IsCensoredToken("sha256:0123456789ab") {
		t.Error("a well-formed token must be recognised")
	}
	// A near-miss that looked like a token used to switch censoring off for the
	// whole finding, so every one of these has to stay false.
	for _, s := range []string{
		"sha256:0123456789a",   // 11 hex
		"sha256:0123456789abc", // 13 hex
		"sha256:0123456789ag",  // non-hex
		"sha256:0123456789AB",  // uppercase
		"sha256:",
		"sha256",
		"",
		"AKIAIOSFODNN7EXAMPLE",
		"md5:0123456789ab",
	} {
		if IsCensoredToken(s) {
			t.Errorf("IsCensoredToken(%q) = true, want false", s)
		}
	}
}

// ── #2: the leaks that actually happened ────────────────────────────

// A 32-hex value beside a real key was printed in full by every output mode,
// because the old unique-character-ratio test could never reach 0.6 for a
// 16-symbol alphabet.
func TestCensorEvidenceCensorsHexNeighbours(t *testing.T) {
	for _, hex := range []string{
		"d41d8cd98f00b204e9800998ecf8427e",                                 // 32 hex, md5
		"9f86d081884c7d659a2feaa0c55ad015a",                                // 32 hex
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // 64 hex
	} {
		line := "SIGNING_HASH=" + hex
		got := CensorEvidence(line, nil)
		if strings.Contains(got, hex) {
			t.Errorf("CensorEvidence(%q) leaked the hex value: %q", line, got)
		}
		if !strings.HasPrefix(got, "SIGNING_HASH=sha256:") {
			t.Errorf("CensorEvidence(%q) = %q, want the key kept and the value tokenised", line, got)
		}
	}
}

// The character class used to stop before "@ $ % ^ & * + ! ~ ?", so
// "P@ssw0rd$ecret!2024" was split: the prefix was tokenised and the rest
// printed verbatim. 23 of 24 characters leaked.
func TestCensorEvidenceDoesNotFragmentPunctuationHeavySecrets(t *testing.T) {
	for _, secret := range []string{
		"P@ssw0rd$ecret!2024",
		"sup3r$3cr3t&value",
		"a1b^c(d)e*f!g@h#i",
		"p%a1$s*s^w&o*r!d?",
		"Tr0ub4dor&3~correct",
	} {
		line := "admin_password=" + secret
		got := CensorEvidence(line, nil)
		if strings.Contains(got, secret) {
			t.Errorf("CensorEvidence(%q) printed the whole secret: %q", line, got)
		}
		if strings.Contains(got, secret[:len(secret)-1]) {
			t.Errorf("CensorEvidence(%q) leaked a prefix: %q", line, got)
		}
	}
}

// A base32 alphabet token has the same low-symbol-count problem as hex.
func TestCensorEvidenceCensorsBase32(t *testing.T) {
	secret := "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOJUW4ZY"
	got := CensorEvidence("api_key="+secret, nil)
	if strings.Contains(got, secret) {
		t.Errorf("base32 secret printed in full: %q", got)
	}
}

// A secret that spans lines cannot be matched by one whole-value ReplaceAll
// against evidence that is assembled one trimmed line at a time.
func TestCensorValueHandlesMultiLineValues(t *testing.T) {
	// The real shape: a value captured across two rendered lines. Evidence is
	// assembled one trimmed line at a time, so a single whole-value ReplaceAll
	// can never line up with it.
	value := "postgres://svc:hunter2longpass@db.internal:5432/\napp_production"
	evidence := "> DSN=postgres://svc:hunter2longpass@db.internal:5432/\n  app_production\n"
	got := CensorValue(evidence, value)
	if strings.Contains(got, "hunter2longpass") || strings.Contains(got, "app_production") {
		t.Errorf("multi-line capture leaked across the line break: %q", got)
	}

	// A capture that only partially overlaps the evidence cannot be handled by
	// exact match at all; the heuristic pass has to cover it.
	partial := "Server=db;Password=S3cr3tPass;Database=app"
	evidence = "> User Id=svc;Password=S3cr3tPass;Database=app\n"
	got = CensorEvidence(evidence, []string{partial})
	if strings.Contains(got, "S3cr3tPass") {
		t.Errorf("partially-overlapping capture leaked its password: %q", got)
	}
}

// Values below this are censored by exact match anyway (they are positively
// known secrets) but a two-line piece of a split value is not censored, because
// replacing every occurrence of two characters would mangle the line.
func TestCensorValueIgnoresTinyPiecesOfSplitValues(t *testing.T) {
	value := "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	text := "> aaaa bbbb cccc\n"
	got := CensorValue(text, value)
	if got != text {
		t.Errorf("tiny split pieces should not be censored: %q -> %q", text, got)
	}
}

// An already-censored token carries no information about the original text and
// must not be hashed again. This produced two different tokens for one secret in
// one report: sha256:78314b11be2e in the Value line and sha256:331c0859e192 in
// the snippet two lines below.
func TestCensorEvidenceDoesNotRehashTokens(t *testing.T) {
	token := SecretToken("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	line := "aws_secret_access_key = " + token
	got := CensorEvidence(line, []string{token})
	if got != line {
		t.Errorf("token was censored again: %q -> %q", line, got)
	}
	if strings.Contains(got, SecretToken(token)) {
		t.Errorf("token was double-hashed: %q", got)
	}
}

// knownSecrets are censored by exact match with no heuristic involved, so even a
// low-entropy or short-alphabet secret is protected when the engine found it.
func TestCensorEvidenceUsesKnownSecretsRegardlessOfShape(t *testing.T) {
	// Deliberately un-secret-looking: a repeated word and a 6-character value.
	// The engine identified them, so they must not be printed.
	for _, secret := range []string{"aaaaaaaaaaaaaaaaaaaaaaaa", "abc123", "0000000000000000"} {
		line := "value=" + secret + " trailing"
		got := CensorEvidence(line, []string{secret})
		if strings.Contains(got, secret) {
			t.Errorf("CensorEvidence(%q, known) leaked: %q", line, got)
		}
	}
}

// Censoring must be idempotent: CensorReport can run after the engine already
// censored the same evidence, and it must not chew on its own output.
func TestCensorEvidenceIsIdempotent(t *testing.T) {
	line := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSIGNING_HASH=d41d8cd98f00b204e9800998ecf8427e"
	known := []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	once := CensorEvidence(line, known)
	twice := CensorEvidence(once, known)
	if once != twice {
		t.Errorf("censoring is not idempotent:\n once:  %q\n twice: %q", once, twice)
	}
}

// ── the heuristic ──────────────────────────────────────────────────

func TestLooksLikeSecretAcceptsRealSecretShapes(t *testing.T) {
	for _, s := range []string{
		"d41d8cd98f00b204e9800998ecf8427e",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOJUW4ZY",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"P@ssw0rd$ecret!2024",
		"ghp_16C7e42F292c6912E7710c838347Ae178B4a",
		"hook-4d9a1f7c3b2e8056af1c94d7e02b8356c",
	} {
		if !looksLikeSecret(s) {
			t.Errorf("looksLikeSecret(%q) = false, want true", s)
		}
	}
}

func TestLooksLikeSecretRejectsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"", "short", "password", // too short
		"HighlightSyntax",      // one character class
		"aaaaaaaaaaaaaaaaaaaa", // one class, low entropy
		"os.environ",           // code path
		"config.database.url",  // code path
		"<<<<<<<",              // punctuation only
		"example",              // one class
	} {
		if looksLikeSecret(s) {
			t.Errorf("looksLikeSecret(%q) = true, want false", s)
		}
	}
}

// Censoring must not swallow the structure of a snippet: the key on the left of
// the assignment has to survive, and so do the delimiters.
func TestCensorEvidenceKeepsSnippetReadable(t *testing.T) {
	line := `admin_password="S3cr3tP@ssw0rd!", db_host=db.internal`
	got := CensorEvidence(line, nil)
	if !strings.HasPrefix(got, "admin_password=") {
		t.Errorf("censoring ate the key name: %q", got)
	}
	if !strings.Contains(got, "db_host=db.internal") {
		t.Errorf("censoring ate an unrelated assignment: %q", got)
	}
	if strings.Contains(got, "S3cr3tP@ssw0rd!") {
		t.Errorf("censoring missed the secret: %q", got)
	}
}

func TestCensorEvidenceHandlesEmptyInputs(t *testing.T) {
	if got := CensorEvidence("", []string{"secretvalue"}); got != "" {
		t.Errorf("empty text = %q", got)
	}
	if got := CensorEvidence("some text here", nil); got == "" {
		t.Error("nil secrets must still run the heuristic")
	}
	if got := CensorEvidence("text", []string{"", SecretToken("x")}); !strings.Contains(got, "text") {
		t.Errorf("empty and token secrets must be skipped: %q", got)
	}
}

// Trailing delimiters must be trimmed, not included, or the token would absorb
// the punctuation and the replacement would change the line's shape.
func TestCensorEvidenceTrimsStructuralDelimiters(t *testing.T) {
	const hex = "d41d8cd98f00b204e9800998ecf8427e"
	token := SecretToken(hex)
	// The delimiters belong to the source line, not to the token: they must
	// survive outside it so the snippet still reads as the original code.
	cases := map[string]string{
		`token = "` + hex + `"`: `token = "` + token + `"`,
		"token = (" + hex + ")": "token = (" + token + ")",
		"token = [" + hex + "]": "token = [" + token + "]",
		"token = " + hex + ",":  "token = " + token + ",",
		"token = " + hex:        "token = " + token,
	}
	for line, want := range cases {
		if got := CensorEvidence(line, nil); got != want {
			t.Errorf("CensorEvidence(%q)\n got %q\nwant %q", line, got, want)
		}
	}
}
