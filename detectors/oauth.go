package detectors

import (
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

// oauthPattern is one compiled detection pattern of the OAuthDetector.
type oauthPattern struct {
	name        string
	regex       *regexp.Regexp
	severity    findings.Severity
	confidence  float64
	tags        []string
	description string
}

// OAuthDetector detects OAuth/API credentials that are not already covered by
// the YAML rules (JWTs, GitHub tokens, and Google keys live in rules/*.yml).
type OAuthDetector struct {
	patterns []oauthPattern
}

func newOAuthPattern(name, pattern string, severity findings.Severity, confidence float64, tags []string, description string) oauthPattern {
	return oauthPattern{
		name:        name,
		regex:       regexp.MustCompile(pattern),
		severity:    severity,
		confidence:  confidence,
		tags:        tags,
		description: description,
	}
}

// NewOAuthDetector creates a new OAuth detector.
func NewOAuthDetector() *OAuthDetector {
	return &OAuthDetector{
		patterns: []oauthPattern{
			newOAuthPattern("oauth_client_secret",
				`(?i)(oauth|client)[_-]?secret\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`,
				findings.SeverityHigh, 0.80,
				[]string{"oauth", "secret", "credentials"}, "OAuth client secret"),

			newOAuthPattern("oauth_access_token",
				`(?i)(oauth|access)[_-]?token\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`,
				findings.SeverityHigh, 0.80,
				[]string{"oauth", "token", "credentials"}, "OAuth access token"),

			newOAuthPattern("gitlab_token",
				`\b(glpat-[A-Za-z0-9\-_]{20,})\b`,
				findings.SeverityHigh, 0.95,
				[]string{"gitlab", "token", "credentials", "vcs"}, "GitLab personal access token"),

			// Anchored to an explicit key/value context: an unanchored
			// fixed-length match would flag every git SHA-1 in sight.
			newOAuthPattern("bitbucket_token",
				`(?i)bitbucket[_-]?(?:token|app[_-]?password)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`,
				findings.SeverityHigh, 0.85,
				[]string{"bitbucket", "token", "credentials", "vcs"}, "Bitbucket app password or token"),

			newOAuthPattern("session_cookie",
				`(?i)(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|sessid|sid)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}['"]?`,
				findings.SeverityMedium, 0.75,
				[]string{"session", "cookie", "credentials"}, "Session cookie or ID"),

			newOAuthPattern("cloud_storage_credentials",
				`(?i)(aws|gcp|azure|s3|gs|blob)\s*(access|secret|key|token|password)\s*[:=]\s*['"]?[A-Za-z0-9/+=@\-_]{20,}['"]?`,
				findings.SeverityHigh, 0.80,
				[]string{"cloud", "storage", "credentials"}, "Cloud storage credentials"),
		},
	}
}

func (d *OAuthDetector) Name() string {
	return "oauth"
}

func (d *OAuthDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	var fResults []findings.Finding
	data, err := file.GetContent()
	if err != nil {
		return nil
	}
	content := string(data)
	lines := strings.Split(content, "\n")

	for _, pattern := range d.patterns {
		matches := pattern.regex.FindAllStringSubmatchIndex(content, maxMatchesPerPattern)
		for _, match := range matches {
			start, end := match[0], match[1]
			if start == -1 || end == -1 {
				continue
			}
			value := content[start:end]
			lineNum, col := locate(content, start)

			sourceLine := ""
			if lineNum-1 >= 0 && lineNum-1 < len(lines) {
				sourceLine = strings.TrimSpace(lines[lineNum-1])
			}

			fResults = append(fResults, findings.Finding{
				Type:       pattern.name,
				Severity:   pattern.severity,
				Confidence: pattern.confidence,
				File:       file.Path,
				Line:       lineNum,
				Column:     col,
				Value:      value,
				Reason:     pattern.description,
				RuleID:     pattern.name,
				Tags:       pattern.tags,
				Context:    extractContext(lines, lineNum-1, 2),
				SourceLine: sourceLine,
			})
		}
	}

	return fResults
}

// locate returns the 1-based line number and column of byte offset pos.
func locate(content string, pos int) (line, col int) {
	line = 1
	lastNewline := -1
	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			lastNewline = i
		}
	}
	col = pos - lastNewline
	return line, col
}
