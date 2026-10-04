package detectors

import (
	"bytes"
	"math"
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

const (
	entropyMinWordLength = 20

	entropyVeryHigh = 5.0
	entropyHigh     = 4.5
	entropyMedium   = 4.0

	lengthVeryLong = 40
	lengthLong     = 32
	lengthMedium   = 24

	scoreVeryHighEntropy = 0.4
	scoreHighEntropy     = 0.3
	scoreMediumEntropy   = 0.2

	scoreVeryLong  = 0.2
	scoreLong      = 0.15
	scoreMediumLen = 0.1

	scoreKeywordMatch = 0.3

	scoreMaxConfidence = 0.9
	scoreMinConfidence = 0.15
)

var secretKeywords = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential|auth|api[_-]?key|access[_-]?token|private[_-]?key|secret[_-]?key)`)

type EntropyDetector struct{}

func NewEntropyDetector() *EntropyDetector {
	return &EntropyDetector{}
}

func (d *EntropyDetector) Name() string {
	return "entropy"
}

var extractStringsRe = regexp.MustCompile(`[A-Za-z0-9\-_+=/]{20,}`)

// definitionKeywords introduce a name rather than a value. A candidate that
// follows one is being defined, whatever its entropy.
var definitionKeywords = []string{
	"def ", "func ", "fn ", "function ", "class ", "struct ", "interface ",
	"enum ", "trait ", "impl ", "type ", "let ", "var ", "const ", "val ",
	"static ", "public ", "private ", "protected ", "internal ", "export ",
	"module ", "package ", "namespace ", "record ", "data ", "sub ",
}

// isIdentifierPosition reports whether the candidate spanning line[start:end]
// is being used as a name.
//
// Three shapes qualify, and all three are certain from context alone:
//
//   - Immediately followed by `(` — in every language this scanner meets, a bare
//     run of identifier characters before an open paren is a definition or a
//     call. This is the reviewer's own example:
//     `def test_backend_asks_about_the_library_without_importing_it(monkeypatch):`
//     was reported at 70% because the line contains the substring `key` inside
//     `monkeypatch` and the function name happens to be 52 characters of
//     English. It cannot be a credential: it is the name of a function.
//   - Immediately preceded by `.` — an attribute or field reference. `super().__secret_key`.
//   - Immediately preceded by a definition keyword — the candidate is being
//     introduced, not assigned.
//
// The preceding-character checks skip whitespace first so that `def  name(` and
// `x . name` read the same as their tightened forms.
func isIdentifierPosition(line []byte, start, end int) bool {
	if next := nextNonSpace(line, end); next >= 0 && line[next] == '(' {
		return true
	}
	i := prevNonSpace(line, start)
	if i < 0 {
		return false
	}
	if line[i] == '.' {
		return true
	}
	prefix := string(line[:i+1])
	for _, kw := range definitionKeywords {
		if strings.HasSuffix(prefix, kw) {
			return true
		}
	}
	return false
}

// nextNonSpace returns the index of the first non-space byte at or after i,
// or -1 if the line ends first.
func nextNonSpace(line []byte, i int) int {
	for ; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t', '\r':
		default:
			return i
		}
	}
	return -1
}

// prevNonSpace returns the index of the last non-space byte strictly before i,
// or -1 if the line starts first.
func prevNonSpace(line []byte, i int) int {
	for j := i - 1; j >= 0; j-- {
		switch line[j] {
		case ' ', '\t', '\r':
		default:
			return j
		}
	}
	return -1
}

func (d *EntropyDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	content, err := file.GetContent()
	if err != nil {
		return nil
	}

	var fResults []findings.Finding
	lineNum := 0
	for rest := content; len(rest) > 0; {
		var raw []byte
		if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
			raw, rest = rest[:idx], rest[idx+1:]
		} else {
			raw, rest = rest, nil
		}
		lineNum++

		// A line shorter than the minimum token length cannot contain a
		// candidate word; skip before touching any regex.
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) < entropyMinWordLength {
			continue
		}

		candidates := extractStringsRe.FindAllIndex(trimmed, -1)
		if len(candidates) == 0 {
			continue
		}

		// The keyword regex is the expensive part; only pay for it once a
		// candidate word exists on the line.
		hasKeyword := secretKeywords.Match(trimmed)

		for _, loc := range candidates {
			word := trimmed[loc[0]:loc[1]]

			// A candidate in identifier position is a name, not a literal.
			// The certainty here comes from the surrounding grammar, not from
			// the token: no threshold can distinguish a 52-character function
			// name from a 52-character secret by its own entropy.
			if isIdentifierPosition(trimmed, loc[0], loc[1]) {
				continue
			}

			// The extraction class includes `=`, so an assignment arrives as one
			// candidate covering both halves: `AUTH_TOKEN=your-token-here`.
			// Judge and report the value, for the same reason the regex rules
			// do — see detectors.credentialValue. Without this the placeholder
			// check never ran on this path at all, and a checked-in
			// `.env.example` reported `changeme` as a 60%-confidence secret.
			col := loc[0]
			if i := bytes.IndexByte(word, '='); i >= 0 && i < len(word)-1 {
				word = word[i+1:]
				col = loc[0] + i + 1
			}
			if LooksLikeExample(string(word)) {
				continue
			}

			entropy := shannonEntropyBytes(word)
			if entropy < entropyMedium {
				continue
			}
			// Keywordless strings in the medium band are mostly UUIDs,
			// hashes, and diff noise — high entropy but not secrets. Only
			// report them once they are unambiguously high, or carry a
			// secret-ish keyword.
			if !hasKeyword && entropy < entropyHigh {
				continue
			}

			confidence := computeEntropyConfidence(entropy, len(word), hasKeyword)
			if confidence < scoreMinConfidence {
				continue
			}
			// Inside a documentation example, or on a comment-only line,
			// require more certainty before reporting: entropy alone is the
			// weakest signal this tool has, and a fenced configuration sample
			// or an explanatory comment is its most common source.
			if heldBackByLineContext(file, lineNum, string(raw), confidence) {
				continue
			}
			// Entropy is line-based, so a large file can emit one finding
			// per line indefinitely. The budget stops that; the engine
			// reports the file as incompletely scanned.
			if !file.ClaimFinding() {
				return fResults
			}

			// Column should be relative to the original line. Only
			// leading whitespace separates raw from trimmed, so the
			// regex offset shifts by exactly that amount.
			leading := len(raw) - len(bytes.TrimLeft(raw, " \t\r\n\v\f"))
			fCol := leading + col

			fResults = append(fResults, findings.Finding{
				Type:       "High Entropy String",
				Severity:   findings.SeverityLow,
				Confidence: confidence,
				File:       file.Path,
				Line:       lineNum,
				Column:     fCol + 1,
				Value:      string(word),
				Reason:     "High-entropy string detected (potential secret)",
				RuleID:     "entropy-high",
				Tags:       []string{"entropy", "potential-secret"},
			})
		}
	}
	return fResults
}

func shannonEntropy(s string) float64 {
	return shannonEntropyBytes([]byte(s))
}

// shannonEntropyBytes computes Shannon entropy using a fixed 256-slot
// frequency table instead of a map: no allocations and no per-byte hashing.
func shannonEntropyBytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func computeEntropyConfidence(entropy float64, length int, hasKeyword bool) float64 {
	score := 0.0

	switch {
	case entropy >= entropyVeryHigh:
		score += scoreVeryHighEntropy
	case entropy >= entropyHigh:
		score += scoreHighEntropy
	case entropy >= entropyMedium:
		score += scoreMediumEntropy
	}

	switch {
	case length >= lengthVeryLong:
		score += scoreVeryLong
	case length >= lengthLong:
		score += scoreLong
	case length >= lengthMedium:
		score += scoreMediumLen
	}

	if hasKeyword {
		score += scoreKeywordMatch
	}

	if score > scoreMaxConfidence {
		score = scoreMaxConfidence
	}
	return score
}
