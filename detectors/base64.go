package detectors

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

// Base64Detector detects secrets that are encoded in base64
// This helps catch secrets that attackers try to hide by encoding them
type Base64Detector struct {
	// Compiled regex patterns for detecting base64 strings
	base64Pattern *regexp.Regexp
	// Minimum length of base64 string to consider
	minLength int
	// Regex detector for scanning decoded content
	regexDetector *RegexDetector
}

// NewBase64Detector creates a new base64 detector
func NewBase64Detector(rulesDir string) (*Base64Detector, error) {
	// Pattern to match base64 strings (with optional padding)
	// Matches strings that look like base64: alphanumeric, +, /, = characters
	pattern := regexp.MustCompile(`\b([A-Za-z0-9+/]{4}){3,}([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b`)

	// Create a regex detector for scanning decoded content
	regexDetector, err := NewRegexDetector(rulesDir)
	if err != nil {
		// If we can't load rules, still create the detector with just base64 detection
		return &Base64Detector{
			base64Pattern: pattern,
			minLength:     16, // Minimum 16 chars (decodes to at least 12 bytes)
			regexDetector: nil,
		}, nil
	}

	return &Base64Detector{
		base64Pattern: pattern,
		minLength:     16,
		regexDetector: regexDetector,
	}, nil
}

func (d *Base64Detector) Name() string {
	return "base64"
}

// isBase64 checks if a string is valid base64
func isBase64(s string) bool {
	// Quick check: base64 strings should have length divisible by 4 (with padding)
	if len(s) < 4 {
		return false
	}
	// Check if it only contains base64 characters
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// decodeBase64 attempts to decode a base64 string
func decodeBase64(s string) ([]byte, error) {
	// Remove any whitespace or newlines
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, " ", "")

	return base64.StdEncoding.DecodeString(s)
}

// extractBase64Strings extracts all potential base64 strings from content
func (d *Base64Detector) extractBase64Strings(content []byte) []string {
	contentStr := string(content)
	matches := d.base64Pattern.FindAllStringSubmatch(contentStr, -1)

	var results []string
	for _, match := range matches {
		if len(match) > 1 {
			candidate := match[0]
			// Verify it's actually valid base64
			if isBase64(candidate) && len(candidate) >= d.minLength {
				results = append(results, candidate)
			}
		}
	}
	return results
}

func (d *Base64Detector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	var fResults []findings.Finding

	// Extract base64 strings from the file content
	base64Strings := d.extractBase64Strings(file.Content)

	// For each base64 string, try to decode and scan
	for _, b64Str := range base64Strings {
		// Decode the base64 string
		decoded, err := decodeBase64(b64Str)
		if err != nil {
			// If decoding fails, try with URL encoding
			decoded, err = base64.URLEncoding.DecodeString(b64Str)
			if err != nil {
				continue
			}
		}

		// Check if decoded content looks like it might contain secrets
		// We look for high entropy or specific patterns
		if len(decoded) < 8 {
			continue // Too short to be interesting
		}

		// Check entropy of decoded content
		entropy := calculateEntropy(decoded)
		if entropy < 3.5 {
			// Low entropy, probably not a secret
			continue
		}

		// Create a temporary file-like structure for scanning
		// We'll create a mock file with the decoded content
		decodedFile := &filesystem.File{
			Path:    file.Path + " (base64 decoded)",
			Content: decoded,
			Size:    int64(len(decoded)),
			Mode:    file.Mode,
			IsBinary: isBinaryContent(decoded),
		}

		// If we have a regex detector, use it to scan the decoded content
		if d.regexDetector != nil {
			findings := d.regexDetector.Detect(decodedFile)
			// Adjust the findings to indicate they were found in base64
			for i := range findings {
				findings[i].Type = "base64_" + findings[i].Type
				findings[i].Reason = "Base64 encoded secret detected: " + findings[i].Reason
				// Add context about the base64 string
				findings[i].Context += "\n[Base64 encoded content detected and decoded]"
			}
			fResults = append(fResults, findings...)
		} else {
			// Without regex detector, just report the base64 string as a finding
			fResults = append(fResults, findings.Finding{
				Type:       "base64_encoded_secret",
				Severity:   findings.Medium,
				Confidence: 0.7,
				File:       file.Path,
				Line:       0, // We don't have line info for base64 content
				Column:     0,
				Value:      b64Str,
				Reason:     "Base64 encoded content with high entropy detected",
				RuleID:     "base64-high-entropy",
				Tags:       []string{"base64", "encoded", "secret"},
				Context:    "Base64 string: " + truncateString(b64Str, 50) + "...",
				SourceLine: "",
			})
		}
	}

	return fResults
}

// calculateEntropy calculates the Shannon entropy of a byte slice
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isBinaryContent is a simple check for binary content
func isBinaryContent(data []byte) bool {
	// Check for null bytes
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
