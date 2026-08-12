package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"minesweep/findings"
)

func TestEngineIntegration(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}

	t.Run("mixed files", func(t *testing.T) {
		dir := t.TempDir()

		fileWithSecret := filepath.Join(dir, ".env")
		os.WriteFile(fileWithSecret, []byte("DATABASE_URL=postgres://user:pass@localhost/db\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0644)

		safeFile := filepath.Join(dir, "README.md")
		os.WriteFile(safeFile, []byte("# My Project\nThis is safe.\n"), 0644)

		privateKey := filepath.Join(dir, "id_rsa")
		os.WriteFile(privateKey, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0gM\n-----END RSA PRIVATE KEY-----\n"), 0644)

		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("expected findings")
		}
		if report.RiskScore == findings.RiskScoreNone {
			t.Fatal("expected non-zero risk")
		}
	})

	t.Run("no secrets", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644)
		os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\n"), 0644)

		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("expected 0 findings for clean project, got %d", len(report.Findings))
		}
		if report.RiskScore != findings.RiskScoreNone {
			t.Fatalf("expected RiskScoreNone, got %d", report.RiskScore)
		}
	})

	t.Run("single file scan", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.txt")
		os.WriteFile(path, []byte("password=supersecret123\n"), 0644)

		report, err := eng.Run(path)
		if err != nil {
			t.Fatalf("Run single file: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("expected findings for single file")
		}
	})
}

func TestEngineEdgeCases(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}
	t.Run("binary named as text", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "innocent.txt")
		os.WriteFile(path, []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}, 0644)

		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("expected at least filetype findings for binary file")
		}
		hasBinaryFinding := false
		for _, f := range report.Findings {
			if f.Type == "Binary File" {
				hasBinaryFinding = true
				break
			}
		}
		if !hasBinaryFinding {
			t.Fatal("expected Binary File finding")
		}
	})

	t.Run("UTF-16 file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "unicode.txt")
		utf16 := []byte{0xFF, 0xFE, 'p', 0x00, 'a', 0x00, 's', 0x00, 's', 0x00, ':', 0x00, 's', 0x00, 'e', 0x00, 'c', 0x00, 'r', 0x00, 'e', 0x00, 't', 0x00}
		os.WriteFile(path, utf16, 0644)

		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("expected findings for UTF-16 file with password-like content")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run empty dir: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("expected 0 findings for empty dir, got %d", len(report.Findings))
		}
	})

	t.Run("file with mixed line endings", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "mixed.txt")
		content := "line1\r\nline2\nline3\rline4\nAKIAIOSFODNN7EXAMPLE\r\n"
		os.WriteFile(path, []byte(content), 0644)

		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		found := false
		for _, f := range report.Findings {
			if f.Type == "AWS Access Key ID" {
				found = true
				if f.Line != 4 {
					t.Logf("AWS key found on line %d (expected 4)", f.Line)
				}
				break
			}
		}
		if !found {
			t.Fatal("expected to find AWS key in mixed line endings file")
		}
	})
}

func TestEngineProfileDifferences(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	secretContent := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0gM\n-----END RSA PRIVATE KEY-----\n")

	sharedDir := t.TempDir()
	os.WriteFile(filepath.Join(sharedDir, "key.pem"), secretContent, 0644)

	profiles := []struct {
		name  string
		check func(t *testing.T, report *findings.RiskReport)
	}{
		{
			name: "developer",
			check: func(t *testing.T, report *findings.RiskReport) {
				for _, f := range report.Findings {
					if f.Type == "SSH Private Key" && !strings.HasPrefix(f.Reason, "warn") {
						t.Errorf("developer profile should warn for SSH key, got reason: %s", f.Reason)
					}
				}
			},
		},
		{
			name: "enterprise",
			check: func(t *testing.T, report *findings.RiskReport) {
				for _, f := range report.Findings {
					if f.Type == "SSH Private Key" && !strings.HasPrefix(f.Reason, "block") {
						t.Errorf("enterprise profile should block SSH key, got reason: %s", f.Reason)
					}
				}
			},
		},
		{
			name: "public-github",
			check: func(t *testing.T, report *findings.RiskReport) {
				for _, f := range report.Findings {
					if f.Type == "SSH Private Key" && !strings.HasPrefix(f.Reason, "block") {
						t.Errorf("public-github profile should block SSH key, got reason: %s", f.Reason)
					}
				}
			},
		},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			eng, err := New(Config{
				RulesDir:    rulesDir,
				ProfilesDir: profilesDir,
				Profile:     p.name,
			})
			if err != nil {
				t.Fatalf("New engine: %v", err)
			}
			report, err := eng.Run(sharedDir)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			p.check(t, report)
		})
	}
}

func TestEngineWithMinesweepIgnore(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, _ := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.env"), []byte("PASSWORD=supersecret\n"), 0644)
	os.WriteFile(filepath.Join(dir, "safe.go"), []byte("package main\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".minesweepignore"), []byte("*.env\n"), 0644)

	report, err := eng.Run(dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, f := range report.Findings {
		if strings.HasSuffix(f.File, ".env") {
			t.Fatalf(".env file should have been ignored, got finding: %s", f.Type)
		}
	}
}

func TestEngineRiskReportBoundaries(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Test Finding",
			Severity:   findings.SeverityInfo,
			Confidence: 0.5,
			File:       "test.txt",
			Line:       1,
			Reason:     "low severity test",
			Tags:       []string{"test"},
		},
	}, nil)

	if report.RiskScore != findings.RiskScoreNone {
		t.Fatalf("expected RiskScoreNone for info severity, got %d", report.RiskScore)
	}
}

func TestEngineDetectorOrder(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}

	detectors := eng.Detectors()
	if len(detectors) < 3 {
		t.Fatalf("expected at least 3 detectors, got %d", len(detectors))
	}

	names := make([]string, len(detectors))
	for i, d := range detectors {
		names[i] = d.Name()
	}
	t.Logf("detector order: %v", names)
}

func TestEngineSymlinkWalk(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, _ := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.txt")
	os.WriteFile(realFile, []byte("safe content"), 0644)

	link := filepath.Join(dir, "link.txt")
	err := os.Symlink("real.txt", link)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}

	report, err := eng.Run(dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	hasSymlinkFinding := false
	for _, f := range report.Findings {
		if f.Type == "Symlink" {
			hasSymlinkFinding = true
			break
		}
	}
	if !hasSymlinkFinding {
		t.Fatal("expected Symlink finding for directory with symlink")
	}
}

// ─── Brutal engine tests ─────────────────────────────────────────────

func TestEngineRunNonexistentPath(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "default"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = eng.Run("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestEngineRunFileNotDir(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	dir := t.TempDir()
	filePath := filepath.Join(dir, "single.txt")
	os.WriteFile(filePath, []byte("hello"), 0644)

	eng, err := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "default"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	report, err := eng.Run(filePath)
	if err != nil {
		t.Fatalf("Run single file: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
}

func TestEngineDeepDirectory(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, _ := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "default",
	})

	dir := t.TempDir()
	current := dir
	depth := 50
	for i := 0; i < depth; i++ {
		current = filepath.Join(current, fmt.Sprintf("sub%d", i))
		if err := os.Mkdir(current, 0755); err != nil {
			t.Skipf("mkdir at depth %d: %v", i, err)
		}
	}
	deepSecret := filepath.Join(current, "secret.env")
	os.WriteFile(deepSecret, []byte("PASSWORD=secret_deep_value\n"), 0644)
	os.WriteFile(filepath.Join(dir, "root.txt"), []byte("safe"), 0644)

	report, err := eng.Run(dir)
	if err != nil {
		t.Fatalf("Run deep dir: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings in deep directory scan")
	}
}

func TestEngineNoProfilesDir(t *testing.T) {
	_, err := New(Config{
		RulesDir:    "../rules",
		ProfilesDir: "/nonexistent/profiles",
		Profile:     "default",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent profiles dir")
	}
}

func TestEnginePolicyFileNotFound(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")

	_, err := New(Config{
		RulesDir:   rulesDir,
		PolicyFile: "/nonexistent/policy.yml",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent policy file")
	}
}

func TestEngineConfigDefaults(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "default"})
	if err != nil {
		t.Fatalf("New with minimal config: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

// ─── Aggressive integration: good / ok / bad project fixtures ──────

func buildFixture(dir, tier string) {
	switch tier {
	case "good":
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644)
		os.WriteFile(filepath.Join(dir, "utils.py"), []byte("def add(a, b):\n    return a + b\n"), 0644)
		os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Project\n\nClean code.\n"), 0644)
		os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example\n\ngo 1.21\n"), 0644)
		os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM golang:1.21\nCOPY . .\n"), 0644)
		os.MkdirAll(filepath.Join(dir, "cmd", "server"), 0755)
		os.WriteFile(filepath.Join(dir, "cmd", "server", "main.go"), []byte("package main\n\nfunc main() { println(\"start\") }\n"), 0644)

	case "ok":
		os.WriteFile(filepath.Join(dir, ".env.example"), []byte("DATABASE_URL=postgres://localhost:5432/mydb\nAPI_KEY=your-api-key-here\n"), 0644)
		os.WriteFile(filepath.Join(dir, "config.yml"), []byte("database:\n  url: postgres://localhost:5432/mydb\n  user: admin\n"), 0644)
		os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"host": "localhost", "port": 8080, "password": "changeme"}`+"\n"), 0644)
		os.WriteFile(filepath.Join(dir, "debug.log"), []byte("[INFO] starting server on port 8080\n[INFO] connected to database\n"), 0644)
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nvar dbUrl = os.Getenv(\"DATABASE_URL\")\n"), 0644)

	case "bad":
		os.WriteFile(filepath.Join(dir, ".env"), []byte(`DATABASE_URL=postgres://admin:SuperSecret1@prod-db.internal:5432/production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SLACK_TOKEN=xoxb-123456789012-1234567890123-abc123def456ghi789jkl
GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz0
PRIVATE_KEY_PATH=/etc/ssl/private/key.pem
`), 0644)
		os.MkdirAll(filepath.Join(dir, "keys"), 0755)
		os.WriteFile(filepath.Join(dir, "keys", "id_rsa"), []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0gM\n-----END RSA PRIVATE KEY-----\n"), 0600)
		os.WriteFile(filepath.Join(dir, "keys", "id_rsa.pub"), []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"), 0644)
		os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(`{
  "endpoint": "https://prod.example.com",
  "api_key": "sk_live_Secr3tK3yV4lu3F0rT3st1ngPurpos3s",
  "db_password": "prod-p@$$w0rd-2024!"
}
`), 0644)
		os.WriteFile(filepath.Join(dir, "token.txt"), []byte("xoxp-987654321098-987654321098-987654321098-abc123def4567890abc123def4567890a\n"), 0644)
		os.MkdirAll(filepath.Join(dir, "config"), 0755)
		os.WriteFile(filepath.Join(dir, "config", "secrets.yml"), []byte("auth:\n  token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9Z1X1jK2FzR0pJIXO6Q64g0lGg\n  admin_key: AC0000000000000000000000000000000\n"), 0644)
		os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.log\nkeys/\n.env\n"), 0644)
	}
}

func TestEngineGoodOkBadFixtures(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	t.Run("good_developer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "good")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "developer"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("good project should have 0 findings under developer, got %d: %v", len(report.Findings), report.Summary)
		}
	})

	t.Run("good_enterprise", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "good")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "enterprise"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("good project should have 0 findings under enterprise, got %d", len(report.Findings))
		}
	})

	t.Run("good_public_github", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "good")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "public-github"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("good project should have 0 findings under public-github, got %d", len(report.Findings))
		}
	})

	t.Run("ok_developer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "ok")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "developer"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		// OK project under developer: expect some low findings (example passwords)
		t.Logf("OK/developer: %d findings, risk=%d, summary=%s", len(report.Findings), report.RiskScore, report.Summary)
	})

	t.Run("ok_enterprise", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "ok")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "enterprise"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		t.Logf("OK/enterprise: %d findings, risk=%d, summary=%s", len(report.Findings), report.RiskScore, report.Summary)
	})

	t.Run("bad_developer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "bad")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "developer"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("bad project should have findings under developer")
		}
		if report.RiskScore < findings.RiskScoreHigh {
			t.Fatalf("bad project should be high/critical risk under developer, got %d", report.RiskScore)
		}
		t.Logf("BAD/developer: %d findings, risk=%d", len(report.Findings), report.RiskScore)
	})

	t.Run("bad_enterprise", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "bad")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "enterprise"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("bad project should have findings under enterprise")
		}
		if report.RiskScore < findings.RiskScoreHigh {
			t.Fatalf("bad project should be high/critical risk under enterprise, got %d", report.RiskScore)
		}
		t.Logf("BAD/enterprise: %d findings, risk=%d", len(report.Findings), report.RiskScore)
	})

	t.Run("bad_public_github", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		buildFixture(dir, "bad")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "public-github"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("bad project should have findings under public-github")
		}
		if report.RiskScore < findings.RiskScoreHigh {
			t.Fatalf("bad project should be high/critical risk under public-github, got %d", report.RiskScore)
		}
		t.Logf("BAD/public-github: %d findings, risk=%d", len(report.Findings), report.RiskScore)
	})

	t.Run("bad_with_ignorefile", func(t *testing.T) {
		dir := t.TempDir()
		buildFixture(dir, "bad")
		eng, _ := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "default"})
		report, err := eng.Run(dir)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		// .gitignore exists with *.log, keys/, .env — but .minesweepignore doesn't exist
		// So gitignore patterns won't affect scan. Findings should be from all files.
		for _, f := range report.Findings {
			t.Logf("  [%s] %s:%d %s", f.Severity, f.File, f.Line, f.Type)
		}
		if len(report.Findings) < 5 {
			t.Fatalf("bad project should have many findings without ignore file, got %d", len(report.Findings))
		}
	})
}

// ─── Stress: concurrent scans on same engine ────────────────────────

func TestEngineConcurrentScans(t *testing.T) {
	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{RulesDir: rulesDir, ProfilesDir: profilesDir, Profile: "default"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	baddir := t.TempDir()
	buildFixture(baddir, "bad")
	gooddir := t.TempDir()
	buildFixture(gooddir, "good")

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var report *findings.RiskReport
			var err error
			if id%2 == 0 {
				report, err = eng.Run(baddir)
			} else {
				report, err = eng.Run(gooddir)
			}
			if err != nil {
				t.Errorf("concurrent Run %d: %v", id, err)
				return
			}
			if report == nil {
				t.Errorf("concurrent Run %d: nil report", id)
			}
		}(i)
	}
	wg.Wait()
}

func TestEngine10kFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10k file test in short mode")
	}

	wd, _ := os.Getwd()
	rulesDir := filepath.Join(wd, "../rules")
	profilesDir := filepath.Join(wd, "../profiles")

	eng, err := New(Config{
		RulesDir:    rulesDir,
		ProfilesDir: profilesDir,
		Profile:     "developer",
	})
	if err != nil {
		t.Fatalf("New engine: %v", err)
	}

	dir := t.TempDir()
	for i := 0; i < 10000; i++ {
		content := fmt.Sprintf("package p%d\n\nconst X = %d\n", i, i)
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d.go", i)), []byte(content), 0644)
	}

	secretsDir := filepath.Join(dir, "secrets")
	os.MkdirAll(secretsDir, 0755)
	for i := 0; i < 100; i++ {
		content := fmt.Sprintf("PASSWORD=secret%d\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", i)
		os.WriteFile(filepath.Join(secretsDir, fmt.Sprintf(".env.%d", i)), []byte(content), 0644)
	}

	var report *findings.RiskReport
	done := make(chan struct{})
	go func() {
		report, err = eng.Run(dir)
		close(done)
	}()

	select {
	case <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("expected findings in 10k file test")
		}
		t.Logf("10k files scanned: %d findings, risk score: %d", len(report.Findings), report.RiskScore)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out scanning 10k files")
	}
}
