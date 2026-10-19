package findings

import (
	"strings"
	"testing"
)

func riskScoreOf(t *testing.T, fs ...Finding) RiskScore {
	t.Helper()
	rep := GenerateRiskReport(fs, nil)
	return rep.RiskScore
}

// A more confident finding must never score lower than a less confident one.
// Monotonicity is the property that makes the number trustworthy; without it a
// reader cannot reason about which way a change moves the score.
func TestRiskScoreMonotonicInConfidence(t *testing.T) {
	low := riskScoreOf(t, Finding{Type: "Generic API Key", Severity: SeverityMedium, Confidence: 0.2, File: "src/app.go"})
	high := riskScoreOf(t, Finding{Type: "Generic API Key", Severity: SeverityMedium, Confidence: 0.95, File: "src/app.go"})
	if high < low {
		t.Fatalf("higher confidence scored lower: 0.95 -> %d, 0.2 -> %d", high, low)
	}
	if high == low {
		t.Fatalf("confidence had no effect on the score (%d == %d)", high, low)
	}
}

func TestRiskScoreMonotonicInVolume(t *testing.T) {
	one := riskScoreOf(t, Finding{Type: "Generic Password", Severity: SeverityMedium, Confidence: 0.7, File: "config.yml"})
	many := make([]Finding, 0, 50)
	for i := 0; i < 50; i++ {
		many = append(many, Finding{Type: "Generic Password", Severity: SeverityMedium, Confidence: 0.7, File: "config.yml"})
	}
	got := riskScoreOf(t, many...)
	if got < one {
		t.Fatalf("adding findings lowered the score: one=%d, many=%d", one, got)
	}
}

// The same credential in a fixture and in a deployment file are not equally
// likely to be live. The fixture is still reported, but it weighs less.
func TestRiskScoreDiscountsTestAndDocPaths(t *testing.T) {
	prod := riskScoreOf(t, Finding{Type: "Generic Password", Severity: SeverityHigh, Confidence: 0.9, File: ".env"})
	test := riskScoreOf(t, Finding{Type: "Generic Password", Severity: SeverityHigh, Confidence: 0.9, File: "tests/fixtures/app_test.go"})
	docs := riskScoreOf(t, Finding{Type: "Generic Password", Severity: SeverityHigh, Confidence: 0.9, File: "docs/setup.md"})

	if prod <= test {
		t.Fatalf("production file should outweigh a test fixture: prod=%d test=%d", prod, test)
	}
	if prod <= docs {
		t.Fatalf("production file should outweigh documentation: prod=%d docs=%d", prod, docs)
	}
}

func TestRiskScorePrivateKeyOutweighsRotatableCredential(t *testing.T) {
	rotatable := riskScoreOf(t, Finding{
		Type: "API Key", Severity: SeverityCritical, Confidence: 0.9,
		File: "config.yml", Tags: []string{"credentials", "api-key"},
	})
	private := riskScoreOf(t, Finding{
		Type: "SSH Private Key", Severity: SeverityCritical, Confidence: 0.9,
		File: "config.yml", Tags: []string{"credentials", "private-key"},
	})
	if private < rotatable {
		t.Fatalf("private key should score at least as high as a rotatable key: private=%d rotatable=%d", private, rotatable)
	}
}

// A live credential in the place credentials live is the case the whole tool
// exists to catch; it must be able to reach the critical band on its own.
func TestRiskScoreSingleCriticalCredential(t *testing.T) {
	got := riskScoreOf(t, Finding{
		Type: "AWS Access Key ID", Severity: SeverityCritical, Confidence: 0.95,
		File: ".env", Tags: []string{"aws", "cloud", "credentials"},
	})
	if got < RiskScoreCritical {
		t.Fatalf("a live AWS key in .env scored %d, want at least the critical band (%d)", got, RiskScoreCritical)
	}
}

// Informational findings are coverage notes, not secrets. A tree that contains
// only those has no detected risk and must read as 0, or naming a binary would
// look risky while naming a clean source tree looks safe.
func TestRiskScoreInfoOnlyIsZero(t *testing.T) {
	got := riskScoreOf(t,
		Finding{Type: "Binary File", Severity: SeverityInfo, Confidence: 1.0, File: "app.exe"},
		Finding{Type: "Symlink", Severity: SeverityInfo, Confidence: 1.0, File: "link"},
	)
	if got != RiskScoreNone {
		t.Fatalf("info-only scan scored %d, want 0", got)
	}
}

func TestRiskScoreCappedAt100(t *testing.T) {
	var fs []Finding
	for i := 0; i < 500; i++ {
		fs = append(fs, Finding{
			Type: "SSH Private Key", Severity: SeverityCritical, Confidence: 1.0,
			File: ".env", Tags: []string{"credentials", "private-key"},
		})
	}
	got := riskScoreOf(t, fs...)
	if got > 100 {
		t.Fatalf("score %d exceeded 100", got)
	}
	if got != 100 {
		t.Fatalf("a tree of private keys scored %d, want 100", got)
	}
}

// The score must be a function of the finding set, not of the order detectors
// happened to emit it in.
func TestRiskScoreOrderIndependent(t *testing.T) {
	fs := []Finding{
		{Type: "A", Severity: SeverityCritical, Confidence: 0.9, File: ".env"},
		{Type: "B", Severity: SeverityMedium, Confidence: 0.4, File: "src/x.go"},
		{Type: "C", Severity: SeverityHigh, Confidence: 0.8, File: "docs/x.md"},
	}
	forward := riskScoreOf(t, fs...)

	reversed := make([]Finding, len(fs))
	for i, f := range fs {
		reversed[len(fs)-1-i] = f
	}
	backward := riskScoreOf(t, reversed...)
	if forward != backward {
		t.Fatalf("score depends on order: forward=%d backward=%d", forward, backward)
	}
}

func TestRiskScoreFactorsExplainTheNumber(t *testing.T) {
	rep := GenerateRiskReport([]Finding{
		{Type: "AWS Access Key ID", Severity: SeverityCritical, Confidence: 0.95, File: ".env"},
		{Type: "Generic Password", Severity: SeverityMedium, Confidence: 0.7, File: "tests/app_test.go"},
	}, nil)

	joined := strings.Join(rep.ScoreFactors, "\n")
	if !strings.Contains(joined, "highest-impact finding") {
		t.Fatalf("score factors do not name the floor: %q", rep.ScoreFactors)
	}
	if !strings.Contains(joined, "discounted") {
		t.Fatalf("score factors do not mention the discounted fixture: %q", rep.ScoreFactors)
	}
}
