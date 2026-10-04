package detectors

import (
	"regexp"

	"minesweep/filesystem"
	"minesweep/findings"
)

// dbPattern is one compiled detection pattern of the DatabaseDetector.
type dbPattern struct {
	// name is the rule ID: stable and machine-facing. label is what the report
	// shows. They used to be one string, so the report headlined findings with
	// internal identifiers and `explain` could not find them.
	name        string
	label       string
	regex       *regexp.Regexp
	gate        literalGate
	severity    findings.Severity
	confidence  float64
	tags        []string
	description string
	// requireValue marks a pattern whose capture spans a whole assignment, so
	// the part after the sign has to be judged rather than the match.
	requireValue bool
}

func newDBPattern(name, label, pattern string, severity findings.Severity, confidence float64, tags []string, description string) dbPattern {
	return dbPattern{
		name:        name,
		label:       label,
		regex:       regexp.MustCompile(pattern),
		gate:        extractLiteralGate(pattern),
		severity:    severity,
		confidence:  confidence,
		tags:        tags,
		description: description,
	}
}

// newDBAssignmentPattern is newDBPattern for rules that capture an assignment
// rather than a bare token.
func newDBAssignmentPattern(name, label, pattern string, severity findings.Severity, confidence float64, tags []string, description string) dbPattern {
	p := newDBPattern(name, label, pattern, severity, confidence, tags, description)
	p.requireValue = true
	return p
}

// DatabaseDetector detects database connection strings and credentials
type DatabaseDetector struct {
	patterns []dbPattern
}

// NewDatabaseDetector creates a new database detector
func NewDatabaseDetector() *DatabaseDetector {
	return &DatabaseDetector{
		patterns: []dbPattern{
			newDBPattern("postgresql_connection_string", "PostgreSQL Connection String",
				`(?i)postgres(?:ql)?(?:\+\w+)?://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "postgresql", "credentials"}, "PostgreSQL connection string with credentials"),

			newDBPattern("mysql_connection_string", "MySQL Connection String",
				`(?i)mysql://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "mysql", "credentials"}, "MySQL connection string with credentials"),

			newDBPattern("mongodb_connection_string", "MongoDB Connection String",
				`(?i)mongodb(?:\+srv)?://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityCritical, 0.90,
				[]string{"database", "mongodb", "credentials"}, "MongoDB connection string with credentials"),

			newDBPattern("redis_connection_string", "Redis Connection String",
				`(?i)redis://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityHigh, 0.85,
				[]string{"database", "redis", "credentials"}, "Redis connection string with credentials"),

			newDBPattern("generic_database_url", "Generic Database URL",
				`(?i)(oracle|mssql|sqlite|mariadb|cockroachdb|clickhouse)://([^:\s]+):([^@\s]+)@[^\s]+`,
				findings.SeverityHigh, 0.80,
				[]string{"database", "credentials"}, "Generic database connection URL with credentials"),

			newDBAssignmentPattern("database_credentials_kv", "Database Credentials",
				`(?i)(?:db|database)[_-]?(?:user|username|user_name|pwd|password|passwd)[ \t]*[:=][ \t]*['"]?[^\s'"]+['"]?`,
				findings.SeverityHigh, 0.75,
				[]string{"database", "credentials"}, "Database credentials in key-value format"),

			// ODBC-style chain: Server=...;...;User Id=...;Password=...
			// Must require the credential keys — an ungrouped alternation
			// here once made the bare word "Server" a HIGH finding.
			newDBPattern("sql_connection_string", "SQL Connection String",
				`(?i)(?:server|data\s*source)=[^;]+(?:;[^;]+)*;(?:user\s*(?:id)?|uid)=[^;]+(?:;[^;]+)*;p(?:assword|wd)=[^;]+`,
				findings.SeverityHigh, 0.85,
				[]string{"database", "sql", "credentials"}, "SQL connection string with credentials"),

			newDBPattern("jdbc_connection_string", "JDBC Connection String",
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

	lowered := file.LoweredContent()
	var li *filesystem.LineIndex
	for _, pattern := range d.patterns {
		if pattern.gate != nil && !pattern.gate.satisfied(data, lowered) {
			continue
		}
		matches := pattern.regex.FindAllSubmatchIndex(data, maxMatchesPerPattern)
		for _, match := range matches {
			start, end := match[0], match[1]
			if start == -1 || end == -1 {
				continue
			}
			if li == nil {
				li = file.Lines()
			}
			lineNum, col := li.LineCol(start)
			value := string(data[start:end])
			if pattern.requireValue && !assignmentValueLooksLikeCredential(value) {
				continue
			}

			// Evidence is attached by the engine to findings that survive
			// filtering, not here — see the note in regex.go.
			if !file.ClaimFinding() {
				return fResults
			}
			fResults = append(fResults, findings.Finding{
				Type:       pattern.label,
				Severity:   pattern.severity,
				Confidence: pattern.confidence,
				File:       file.Path,
				Line:       lineNum,
				Column:     col,
				Value:      value,
				Reason:     pattern.description,
				RuleID:     pattern.name,
				Tags:       pattern.tags,
			})
		}
	}

	return fResults
}

// BuiltInRules describes the DatabaseDetector's patterns as Rule values so
// `minesweep explain <rule-id>` can account for them.
//
// The detector's patterns are compiled in Go rather than loaded from YAML, so
// they were invisible to `explain`, which only reads the rule directory. A
// finding whose rule ID could not be explained was an internal identifier
// leaking into the user's workflow.
func (d *DatabaseDetector) BuiltInRules() []Rule {
	out := make([]Rule, 0, len(d.patterns))
	for _, p := range d.patterns {
		out = append(out, Rule{
			ID:          p.name,
			Type:        "regex",
			Name:        p.label,
			Description: p.description,
			Severity:    p.severity.String(),
			Tags:        append([]string(nil), p.tags...),
			BuiltIn:     true,
		})
	}
	return out
}
