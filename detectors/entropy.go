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

func (d *EntropyDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	content, err := file.GetContent()
	if err != nil {
		return nil
	}

	var fResults []findings.Finding
	lines := bytes.Split(content, []byte("\n"))

	for lineNum, rawLine := range lines {
		lineStr := string(rawLine)
		trimmed := strings.TrimSpace(lineStr)
		if trimmed == "" {
			continue
		}

		hasKeyword := secretKeywords.MatchString(trimmed)

		words := extractStrings(trimmed)
		for _, word := range words {
			if len(word) < entropyMinWordLength {
				continue
			}

			entropy := shannonEntropy(word)
			if entropy < entropyMedium {
				continue
			}

			confidence := computeEntropyConfidence(entropy, len(word), hasKeyword)
			if confidence < scoreMinConfidence {
				continue
			}

			// Column should be relative to the original line, not the
			// whitespace-trimmed one.
			col := strings.Index(lineStr, word)
			if col < 0 {
				col = strings.Index(trimmed, word)
			}

			fResults = append(fResults, findings.Finding{
				Type:       "High Entropy String",
				Severity:   findings.SeverityLow,
				Confidence: confidence,
				File:       file.Path,
				Line:       lineNum + 1,
				Column:     col + 1,
				Value:      word,
				Reason:     "High-entropy string detected (potential secret)",
				RuleID:     "entropy-high",
				Tags:       []string{"entropy", "potential-secret"},
				SourceLine: trimmed,
			})
		}
	}
	return fResults
}

var extractStringsRe = regexp.MustCompile(`[A-Za-z0-9\-_+=/]{20,}`)

func extractStrings(line string) []string {
	return extractStringsRe.FindAllString(line, -1)
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
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
