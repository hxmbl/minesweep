package detectors

import (
	"encoding/base64"
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

// NewBase64Detector creates a new base64 detector with its own regex detector
func NewBase64Detector(rulesDir string) (*Base64Detector, error) {
	regexDetector, err := NewRegexDetector(rulesDir)
	if err != nil {
		return nil, err
	}
	return NewBase64DetectorWithRegex(regexDetector), nil
}

// NewBase64DetectorWithRegex creates a base64 detector that reuses an existing
// RegexDetector, so rules are compiled and held only once per scan.
func NewBase64DetectorWithRegex(regexDetector *RegexDetector) *Base64Detector {
	pattern := regexp.MustCompile(`\b([A-Za-z0-9+/]{4}){3,}([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b`)
	return &Base64Detector{
		base64Pattern: pattern,
		minLength:     16, // Minimum 16 chars (decodes to at least 12 bytes)
		regexDetector: regexDetector,
	}
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
	for i := 0; i < len(s); i++ {
		c := s[i]
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

// maxBase64Candidates caps how many base64 candidate strings are decoded and
// rescanned per file.
const maxBase64Candidates = 1000

// extractBase64Strings extracts all potential base64 strings from content.
// Matching runs on the raw bytes so the whole file never has to be copied
// into a string first.
func (d *Base64Detector) extractBase64Strings(content []byte) []string {
	matches := d.base64Pattern.FindAllSubmatchIndex(content, maxBase64Candidates)

	var results []string
	for _, match := range matches {
		if len(match) > 3 {
			start, end := match[0], match[1]
			if start == -1 || end == -1 {
				continue
			}
			candidate := string(content[start:end])
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
	content, err := file.GetContent()
	if err != nil {
		return nil
	}
	base64Strings := d.extractBase64Strings(content)

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
		entropy := shannonEntropyBytes(decoded)
		if entropy < 3.5 {
			// Low entropy, probably not a secret
			continue
		}

		// Create a temporary file-like structure for scanning
		// We'll create a mock file with the decoded content
		decodedFile := &filesystem.File{
			Path:     file.Path + " (base64 decoded)",
			Content:  decoded,
			Size:     int64(len(decoded)),
			Mode:     file.Mode,
			IsBinary: isBinaryContent(decoded),
		}

		// If we have a regex detector, use it to scan the decoded content
		if d.regexDetector != nil {
			decodedFindings := d.regexDetector.Detect(decodedFile)
			// Adjust the findings to indicate they were found in base64
			for i := range decodedFindings {
				decodedFindings[i].Type = "base64_" + decodedFindings[i].Type
				decodedFindings[i].Reason = "Base64 encoded secret detected: " + decodedFindings[i].Reason
				// Add context about the base64 string
				decodedFindings[i].Context += "\n[Base64 encoded content detected and decoded]"
			}
			fResults = append(fResults, decodedFindings...)
		} else {
			// Without regex detector, just report the base64 string as a finding
			fResults = append(fResults, findings.Finding{
				Type:       "base64_encoded_secret",
				Severity:   findings.SeverityMedium,
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
