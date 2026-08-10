package detectors

import (
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

// DatabaseDetector detects database connection strings and credentials
type DatabaseDetector struct {
	patterns []struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}
}

// NewDatabaseDetector creates a new database detector
func NewDatabaseDetector() *DatabaseDetector {
	d := &DatabaseDetector{}

	// PostgreSQL connection strings
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "postgresql_connection_string",
		regex:       regexp.MustCompile(`(?i)postgresql(?:\+\w+)?://([^:]+):([^@]+)@[^\s]+`),
		severity:   findings.Critical,
		confidence:  0.90,
		tags:       []string{"database", "postgresql", "credentials"},
		description: "PostgreSQL connection string with credentials",
	})

	// MySQL connection strings
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "mysql_connection_string",
		regex:       regexp.MustCompile(`(?i)mysql://([^:]+):([^@]+)@[^\s]+`),
		severity:   findings.Critical,
		confidence:  0.90,
		tags:       []string{"database", "mysql", "credentials"},
		description: "MySQL connection string with credentials",
	})

	// MongoDB connection strings
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "mongodb_connection_string",
		regex:       regexp.MustCompile(`(?i)mongodb(?:\+srv)?://([^:]+):([^@]+)@[^\s]+`),
		severity:   findings.Critical,
		confidence:  0.90,
		tags:       []string{"database", "mongodb", "credentials"},
		description: "MongoDB connection string with credentials",
	})

	// Redis connection strings
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "redis_connection_string",
		regex:       regexp.MustCompile(`(?i)redis://([^:]+):([^@]+)@[^\s]+`),
		severity:   findings.High,
		confidence:  0.85,
		tags:       []string{"database", "redis", "credentials"},
		description: "Redis connection string with credentials",
	})

	// Generic database URL with credentials
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "generic_database_url",
		regex:       regexp.MustCompile(`(?i)(oracle|mssql|sqlite|mariadb|cockroachdb|clickhouse)://([^:]+):([^@]+)@[^\s]+`),
		severity:   findings.High,
		confidence:  0.80,
		tags:       []string{"database", "credentials"},
		description: "Generic database connection URL with credentials",
	})

	// Database credentials in key-value format
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "database_credentials_kv",
		regex:       regexp.MustCompile(`(?i)(db|database)[_-]?(user|username|user_name|pwd|password|passwd)\s*[:=]\s*['"]?[^\s'"]+['"]?`),
		severity:   findings.High,
		confidence:  0.75,
		tags:       []string{"database", "credentials"},
		description: "Database credentials in key-value format",
	})

	// SQL connection strings (ODBC style)
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "sql_connection_string",
		regex:       regexp.MustCompile(`(?i)Server|Data Source=[^;]+;User ID=[^;]+;Password=[^;]+`),
		severity:   findings.High,
		confidence:  0.85,
		tags:       []string{"database", "sql", "credentials"},
		description: "SQL connection string with credentials",
	})

	// JDBC connection strings
	d.patterns = append(d.patterns, struct {
		name        string
		regex       *regexp.Regexp
		severity   findings.Severity
		confidence  float64
		tags       []string
		description string
	}{
		name:        "jdbc_connection_string",
		regex:       regexp.MustCompile(`(?i)jdbc:[a-z0-9]+://[^:]+:[^@]+@[^\s]+`),
		severity:   findings.High,
		confidence:  0.85,
		tags:       []string{"database", "jdbc", "credentials"},
		description: "JDBC connection string with credentials",
	})

	return d
}

func (d *DatabaseDetector) Name() string {
	return "database"
}

func (d *DatabaseDetector) Detect(file *filesystem.File) []findings.Finding {
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
				Context:    extractContext(lines, lineNum-1, 2),
				SourceLine: sourceLine,
			})
		}
	}

	return fResults
}

func extractContext(lines []string, center, radius int) string {
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
