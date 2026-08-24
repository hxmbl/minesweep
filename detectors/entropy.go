package detectors

import (
	"bytes"
	"math"
	"regexp"

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

			entropy := shannonEntropyBytes(word)
			if entropy < entropyMedium {
				continue
			}

			confidence := computeEntropyConfidence(entropy, len(word), hasKeyword)
			if confidence < scoreMinConfidence {
				continue
			}

			// Column should be relative to the original line. Only
			// leading whitespace separates raw from trimmed, so the
			// regex offset shifts by exactly that amount.
			leading := len(raw) - len(bytes.TrimLeft(raw, " \t\r\n\v\f"))
			col := leading + loc[0]

			fResults = append(fResults, findings.Finding{
				Type:       "High Entropy String",
				Severity:   findings.SeverityLow,
				Confidence: confidence,
				File:       file.Path,
				Line:       lineNum,
				Column:     col + 1,
				Value:      string(word),
				Reason:     "High-entropy string detected (potential secret)",
				RuleID:     "entropy-high",
				Tags:       []string{"entropy", "potential-secret"},
				SourceLine: string(bytes.TrimRight(raw, "\r")),
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
