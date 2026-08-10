package detectors

import (
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

// OAuthDetector detects OAuth tokens, bearer tokens, and other API credentials
type OAuthDetector struct {
	patterns []struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}
}

// NewOAuthDetector creates a new OAuth detector
func NewOAuthDetector() *OAuthDetector {
	d := &OAuthDetector{}

	// Bearer tokens (generic)
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "bearer_token",
		regex:       regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
		severity:   findings.High,
		confidence:  0.85,
		tags:       []string{"oauth", "bearer", "token", "credentials"},
		description: "Bearer token (JWT format)",
	})

	// Generic JWT tokens
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "jwt_token",
		regex:       regexp.MustCompile(`\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b`),
		severity:   findings.High,
		confidence:  0.75,
		tags:       []string{"jwt", "token", "credentials"},
		description: "JWT token detected",
	})

	// OAuth client secrets
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "oauth_client_secret",
		regex:       regexp.MustCompile(`(?i)(oauth|client)[_-]?secret\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`),
		severity:   findings.High,
		confidence:  0.80,
		tags:       []string{"oauth", "secret", "credentials"},
		description: "OAuth client secret",
	})

	// OAuth access tokens
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "oauth_access_token",
		regex:       regexp.MustCompile(`(?i)(oauth|access)[_-]?token\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?`),
		severity:   findings.High,
		confidence:  0.80,
		tags:       []string{"oauth", "token", "credentials"},
		description: "OAuth access token",
	})

	// GitHub tokens
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "github_token",
		regex:       regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b`),
		severity:   findings.High,
		confidence:  0.95,
		tags:       []string{"github", "token", "credentials"},
		description: "GitHub personal access token",
	})

	// GitLab tokens
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "gitlab_token",
		regex:       regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20,})\b`),
		severity:   findings.High,
		confidence:  0.95,
		tags:       []string{"gitlab", "token", "credentials"},
		description: "GitLab personal access token",
	})

	// Bitbucket tokens
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "bitbucket_token",
		regex:       regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`),
		severity:   findings.High,
		confidence:  0.70,
		tags:       []string{"bitbucket", "token", "credentials"},
		description: "Bitbucket app password or token",
	})

	// Google API keys
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "google_api_key",
		regex:       regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		severity:   findings.High,
		confidence:  0.90,
		tags:       []string{"google", "api-key", "credentials"},
		description: "Google API key",
	})

	// Google OAuth client IDs
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "google_oauth_client_id",
		regex:       regexp.MustCompile(`\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b`),
		severity:   findings.Medium,
		confidence:  0.85,
		tags:       []string{"google", "oauth", "credentials"},
		description: "Google OAuth client ID",
	})

	// Session cookies
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "session_cookie",
		regex:       regexp.MustCompile(`(?i)(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|sessid|sid)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}['"]?`),
		severity:   findings.Medium,
		confidence:  0.75,
		tags:       []string{"session", "cookie", "credentials"},
		description: "Session cookie or ID",
	})

	// Cloud storage credentials
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "cloud_storage_credentials",
		regex:       regexp.MustCompile(`(?i)(aws|gcp|azure|s3|gs|blob)\s*(access|secret|key|token|password)\s*[:=]\s*['"]?[A-Za-z0-9\/+=@\-_]{20,}['"]?`),
		severity:   findings.High,
		confidence:  0.80,
		tags:       []string{"cloud", "storage", "credentials"},
		description: "Cloud storage credentials",
	})

	return d
}

func (d *OAuthDetector) Name() string {
	return "oauth"
}

func (d *OAuthDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	var fResults []findings.Finding
	content := string(file.Content)
	lines := strings.Split(content, "\n")

	for _, pattern := range d.patterns {
		matches := pattern.regex.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			// Extract the full match
			start := match[0]
			end := match[1]
			if start == -1 || end == -1 {
				continue
			}
			value := content[start:end]

			// Get line number
			lineNum := 1
			for i := 0; i < start && i < len(content); i++ {
				if content[i] == '\n' {
					lineNum++
				}
			}

			// Get source line
			sourceLine := ""
			if lineNum-1 >= 0 && lineNum-1 < len(lines) {
				sourceLine = strings.TrimSpace(lines[lineNum-1])
			}

			// Get column
			col := start
			for i := start - 1; i >= 0 && content[i] != '\n'; i-- {
				col--
			}
			col++

			fResults = append(fResults, findings.Finding{
				Type:       pattern.name,
				Severity:   pattern.severity,
				Confidence:  pattern.confidence,
				File:       file.Path,
				Line:       lineNum,
				Column:     col,
				Value:      value,
				Reason:     pattern.description,
				RuleID:     pattern.name,
				Tags:       pattern.tags,
				Context:    extractOAuthContext(lines, lineNum-1, 2),
				SourceLine: sourceLine,
			})
		}
	}

	return fResults
}

func extractOAuthContext(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == center {
			prefix = "> "
		}
		sb.WriteString(prefix)
		sb.WriteString(strings.TrimSpace(lines[i]))
		sb.WriteString("\n")
	}
	return sb.String()
}
