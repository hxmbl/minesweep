package detectors

import (
	"bytes"
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
	// Trailing \b fails for padded tokens ("...TEU=" ends with "="), so the end
	// boundary is a required non-base64 terminator (or end of input) instead
	// of a word edge. Leading \b also misses tokens that start with "+" or
	// "/", so the start boundary is an explicit non-base64 anchor. Group 1 is
	// the whole token.
	pattern := regexp.MustCompile(`(^|[^A-Za-z0-9+/=])((?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))($|[^A-Za-z0-9+/=])`)
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

// base64Candidate is a decoded-able token plus its byte span in the original
// file content, so findings about the decoded payload can be traced back to a
// line and column the user can actually open.
type base64Candidate struct {
	value string
	start int
	end   int
}

// extractBase64Strings extracts all potential base64 strings from content,
// retaining their offsets. Matching runs on the raw bytes so the whole file
// never has to be copied into a string first.
func (d *Base64Detector) extractBase64Strings(content []byte) []base64Candidate {
	matches := d.base64Pattern.FindAllSubmatchIndex(content, maxBase64Candidates)

	var results []base64Candidate
	for _, match := range matches {
		if len(match) > 5 {
			// Group 2 is the token itself; group 0 additionally includes the
			// leading anchor and trailing terminator characters.
			start, end := match[4], match[5]
			if start == -1 || end == -1 {
				continue
			}
			candidate := content[start:end]
			// Verify it's actually valid base64
			if isBase64(string(candidate)) && len(candidate) >= d.minLength {
				results = append(results, base64Candidate{
					value: string(candidate),
					start: start,
					end:   end,
				})
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
	candidates := d.extractBase64Strings(content)

	var li *filesystem.LineIndex
	// remap carries a finding produced against the decoded payload back to
	// the original file, using the decoded value's position inside the token.
	// Without this, findings pointed at "<path> (base64 decoded)" with
	// decoded-only line numbers the user cannot open.
	remap := func(f findings.Finding, decoded []byte, cand base64Candidate) findings.Finding {
		if li == nil {
			li = file.Lines()
		}
		decodedOffset := bytes.Index(decoded, []byte(f.Value))
		if decodedOffset < 0 {
			decodedOffset = 0
		}
		origOffset := decodedOffsetToOrig(decodedOffset, cand.start)
		if origOffset > cand.end {
			origOffset = cand.end
		}
		line, col := li.LineCol(origOffset)
		f.File = file.Path
		f.Line = line
		f.Column = col
		f.SourceLine = strings.TrimSpace(li.LineText(line - 1))
		f.Context = li.Context(line-1, 2)
		return f
	}

	// For each base64 string, try to decode and scan
	for _, cand := range candidates {
		// Decode the base64 string
		decoded, err := decodeBase64(cand.value)
		if err != nil {
			// If decoding fails, try with URL encoding
			decoded, err = base64.URLEncoding.DecodeString(cand.value)
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

		// If we have a regex detector, use it to scan the decoded content
		if d.regexDetector != nil {
			decodedFile := &filesystem.File{
				Path:     file.Path + " (base64 decoded)",
				Content:  decoded,
				Size:     int64(len(decoded)),
				Mode:     file.Mode,
				IsBinary: isBinaryContent(decoded),
			}
			decodedFindings := d.regexDetector.Detect(decodedFile)
			// Adjust the findings to indicate they were found in base64
			for i := range decodedFindings {
				decodedFindings[i] = remap(decodedFindings[i], decoded, cand)
				decodedFindings[i].Type = "base64_" + decodedFindings[i].Type
				decodedFindings[i].Reason = "Base64 encoded secret detected: " + decodedFindings[i].Reason
				// Add context about the base64 string
				decodedFindings[i].Context += "\n[Base64 encoded content detected and decoded]"
			}
			fResults = append(fResults, decodedFindings...)
		} else {
			// Without regex detector, just report the base64 string as a finding
			if li == nil {
				li = file.Lines()
			}
			line, col := li.LineCol(cand.start)
			fResults = append(fResults, findings.Finding{
				Type:       "base64_encoded_secret",
				Severity:   findings.SeverityMedium,
				Confidence: 0.7,
				File:       file.Path,
				Line:       line,
				Column:     col,
				Value:      cand.value,
				Reason:     "Base64 encoded content with high entropy detected",
				RuleID:     "base64-high-entropy",
				Tags:       []string{"base64", "encoded", "secret"},
				Context:    "Base64 string: " + truncateString(cand.value, 50) + "...",
				SourceLine: strings.TrimSpace(li.LineText(line - 1)),
			})
		}
	}

	return fResults
}

// decodedOffsetToOrig maps a byte offset within a decoded base64 payload back
// to an offset within the original content. Base64 packs 3 bytes into 4
// characters, so decoded byte d is carried by base64 character (d/3)*4+(d%3);
// final padding truncating the last group makes this approximate by at most a
// couple of columns, which is fine for line/column reporting.
func decodedOffsetToOrig(decodedOffset, candStart int) int {
	return candStart + (decodedOffset/3)*4 + (decodedOffset % 3)
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
