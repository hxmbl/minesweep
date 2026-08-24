package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"minesweep/filesystem"
)

func newTestFile(t *testing.T, content string) *filesystem.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := filesystem.NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestDatabaseDetector_NoServerFalsePositive guards against regression of the
// sql_connection_string alternation bug, where a bare word "server" anywhere
// in a file produced a HIGH severity finding.
func TestDatabaseDetector_NoServerFalsePositive(t *testing.T) {
	d := NewDatabaseDetector()

	benign := []string{
		"the server handles requests",
		`Server = "localhost"`,
		"server.listen(8080)",
		"Data Source=localdb\n",
	}
	for _, content := range benign {
		f := newTestFile(t, content)
		if got := d.Detect(f); len(got) != 0 {
			t.Errorf("benign input %q: expected 0 findings, got %d (%s)", content, len(got), got[0].Type)
		}
	}
}

func TestDatabaseDetector_SQLConnectionString(t *testing.T) {
	d := NewDatabaseDetector()

	cases := []string{
		"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;",
		"Data Source=host;Initial Catalog=db;Uid=admin;Pwd=hunter2;",
		"server=localhost;uid=root;password=s3cret",
	}
	for _, content := range cases {
		f := newTestFile(t, content)
		got := d.Detect(f)
		if len(got) != 1 {
			t.Errorf("input %q: expected 1 finding, got %d", content, len(got))
			continue
		}
		if got[0].RuleID != "sql_connection_string" {
			t.Errorf("input %q: unexpected rule %q", content, got[0].RuleID)
		}
	}
}

func TestDatabaseDetector_ConnectionStrings(t *testing.T) {
	d := NewDatabaseDetector()

	cases := []struct {
		content string
		ruleID  string
	}{
		{"postgres://user:secret@localhost:5432/db\n", "postgresql_connection_string"},
		{"mongodb+srv://admin:hunter2@cluster.mongodb.net/db\n", "mongodb_connection_string"},
		{"redis://default:hunter2@redis.internal:6379/0\n", "redis_connection_string"},
		{"mysql://app:s3cret@db.internal:3306/prod\n", "mysql_connection_string"},
		{"DB_PASSWORD=supersecret123\n", "database_credentials_kv"},
	}

	for _, tc := range cases {
		f := newTestFile(t, tc.content)
		got := d.Detect(f)
		found := false
		for _, g := range got {
			if g.RuleID == tc.ruleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("input %q: expected rule %q, got %d findings", tc.content, tc.ruleID, len(got))
		}
	}
}
