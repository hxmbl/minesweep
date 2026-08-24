package detectors

import (
	"regexp"
	"strings"

	"minesweep/filesystem"
	"minesweep/findings"
)

// dbPattern is one compiled detection pattern of the DatabaseDetector.
type dbPattern struct {
	name        string
	regex       *regexp.Regexp
	severity    findings.Severity
	confidence  float64
	tags        []string
	description string
}

func newDBPattern(name, pattern string, severity findings.Severity, confidence float64, tags []string, description string) dbPattern {
	return dbPattern{
		name:        name,
		regex:       regexp.MustCompile(pattern),
		severity:    severity,
		confidence:  confidence,
		tags:        tags,
		description: description,
	}
}

// DatabaseDetector detects database connection strings and credentials
type DatabaseDetector struct {
	patterns []dbPattern
}

// NewDatabaseDetector creates a new database detector
func NewDatabaseDetector() *DatabaseDetector {
	return &DatabaseDetector{
		patterns: []dbPattern{
			newDBPattern("postgresql_connection_string",
				`(?i)postgres(?:ql)?(?:\+\w+)?://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "postgresql", "credentials"}, "PostgreSQL connection string with credentials"),

			newDBPattern("mysql_connection_string",
				`(?i)mysql://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "mysql", "credentials"}, "MySQL connection string with credentials"),

			newDBPattern("mongodb_connection_string",
				`(?i)mongodb(?:\+srv)?://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "mongodb", "credentials"}, "MongoDB connection string with credentials"),

			newDBPattern("redis_connection_string",
				`(?i)redis://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityHigh, 0.85,
				[]string{"database", "redis", "credentials"}, "Redis connection string with credentials"),

			newDBPattern("generic_database_url",
				`(?i)(oracle|mssql|sqlite|mariadb|cockroachdb|clickhouse)://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityHigh, 0.80,
				[]string{"database", "credentials"}, "Generic database connection URL with credentials"),

			newDBPattern("database_credentials_kv",
				`(?i)(?:db|database)[_-]?(?:user|username|user_name|pwd|password|passwd)\s*[:=]\s*['"]?[^\s'"]+['"]?`,
				findings.SeverityHigh, 0.75,
				[]string{"database", "credentials"}, "Database credentials in key-value format"),

			// ODBC-style chain: Server=...;...;User Id=...;Password=...
			// Must require the credential keys — an ungrouped alternation
			// here once made the bare word "Server" a HIGH finding.
			newDBPattern("sql_connection_string",
				`(?i)(?:server|data\s*source)=[^;]+(?:;[^;]+)*;(?:user\s*(?:id)?|uid)=[^;]+(?:;[^;]+)*;p(?:assword|wd)=[^;]+`,
				findings.SeverityHigh, 0.85,
				[]string{"database", "sql", "credentials"}, "SQL connection string with credentials"),

			newDBPattern("jdbc_connection_string",
				`(?i)jdbc:[a-z0-9]+://[^:\s]+:[^@\s]+@[^\s]+`,
				findings.SeverityHigh, 0.85,
				[]string{"database", "jdbc", "credentials"}, "JDBC connection string with credentials"),
		},
	}
}

func (d *DatabaseDetector) Name() string {
	return "database"
}

func (d *DatabaseDetector) Detect(file *filesystem.File) []findings.Finding {
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
