package engine

import (
	fx "minesweep/internal/fixtures"
	"os"
	"path/filepath"
	"testing"
)

// binaryish is content that filesystem.IsBinary classifies as binary: a NUL
// byte in the first block.
var binaryish = []byte("\x00\x01\x02 not text \x00 " + fx.AWSAccessKeyID() + " \xff")

func writeTarget(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A binary named directly is the answer to the question asked, not a filter that
// dropped one item from a tree. Content detectors never run on it, so the scan
// read none of it: it must be reported incomplete rather than clean.
func TestBinaryTargetIsIncomplete(t *testing.T) {
	target := writeTarget(t, "blob.dat", binaryish)
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rep, err := e.Run(target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.Incomplete {
		t.Errorf("binary target reported a complete scan; want incomplete: %+v", rep.IncompleteReasons)
	}
	if len(rep.IncompleteReasons) != 1 || rep.IncompleteReasons[0] != ReasonBinaryTarget {
		t.Errorf("IncompleteReasons = %q, want [%q]", rep.IncompleteReasons, ReasonBinaryTarget)
	}
}

// The scan must still flag the file as binary: a reader needs to be told the
// content was withheld, not just handed a non-zero exit code.
func TestBinaryTargetStillReportsBinaryFinding(t *testing.T) {
	target := writeTarget(t, "blob.dat", binaryish)
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rep, err := e.Run(target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Type == "Binary File" {
			found = true
			if f.Context == "" || f.SourceLine == "" {
				t.Error("binary finding carries no evidence placeholder")
			}
		}
	}
	if !found {
		t.Errorf("no Binary File finding; got %d findings", len(rep.Findings))
	}
}

// safe_to_share is derived from the risk score, and a withheld-content scan has
// a risk score of 0. That combination is the false clean this guards against:
// the file may well hold a credential, and nothing here knows.
func TestBinaryTargetDoesNotClaimSafeToShare(t *testing.T) {
	target := writeTarget(t, "blob.dat", binaryish)
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rep, err := e.Run(target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.RiskScore != 0 {
		t.Fatalf("precondition: RiskScore = %d, want 0", rep.RiskScore)
	}
	if !rep.Incomplete {
		t.Error("scan not marked incomplete, so a zero score still reads as clean")
	}
}

// Binaries are expected inside a tree: they are already reported as a per-cause
// skip. Flagging every repo that contains a PNG would make exit 2 meaningless,
// so the incomplete signal is scoped to a hand-named target only.
func TestBinaryInDirectoryStaysComplete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob.dat"), binaryish, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing to see\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := e.Run(dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Incomplete {
		t.Errorf("directory scan marked incomplete because of a binary file: %q", rep.IncompleteReasons)
	}
}

// A text target is unaffected: incomplete stays false so a clean file still
// exits 0.
func TestTextTargetStaysComplete(t *testing.T) {
	target := writeTarget(t, "ok.txt", []byte("nothing to see\n"))
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rep, err := e.Run(target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Incomplete {
		t.Errorf("text target marked incomplete: %q", rep.IncompleteReasons)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("clean text produced findings: %+v", rep.Findings)
	}
}
