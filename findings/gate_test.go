package findings

import "testing"

// The compound gate exists because --fail-on read one axis while the report
// displayed two. These tests pin the parsing and the semantics; the CLI's use of
// them is covered by the exit-code tests.
func TestParseGate(t *testing.T) {
	cases := []struct {
		in         string
		wantSev    Severity
		wantConf   float64
		wantHasCon bool
	}{
		{"low", SeverityLow, 0, false},
		{"critical", SeverityCritical, 0, false},
		{"HIGH", SeverityHigh, 0, false},
		{"  high  ", SeverityHigh, 0, false},
		{"high@60%", SeverityHigh, 0.60, true},
		{"high@0.6", SeverityHigh, 0.60, true},
		{"low@100%", SeverityLow, 1.0, true},
		{"info@0%", SeverityInfo, 0, false}, // an explicit 0% floor is no floor
		{"medium@85%", SeverityMedium, 0.85, true},
	}
	for _, tc := range cases {
		g, err := ParseGate(tc.in)
		if err != nil {
			t.Errorf("ParseGate(%q) error: %v", tc.in, err)
			continue
		}
		if g.Severity != tc.wantSev || g.HasConfidenceFloor() != tc.wantHasCon {
			t.Errorf("ParseGate(%q) = %+v, want severity %v hasConf %v",
				tc.in, g, tc.wantSev, tc.wantHasCon)
			continue
		}
		if tc.wantHasCon && g.MinConfidence != tc.wantConf {
			t.Errorf("ParseGate(%q) confidence = %v, want %v", tc.in, g.MinConfidence, tc.wantConf)
		}
	}
}

// A mistyped gate is indistinguishable from a working one if it is tolerated,
// so every malformed form is an error rather than a fallback.
func TestParseGateRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"", "  ", "bogus", "high@", "high@abc", "high@%", "high@101%",
		"high@150%", "high@-1", "high@1.5", "high@60%%", "high@60%@20%",
	} {
		if g, err := ParseGate(in); err == nil {
			t.Errorf("ParseGate(%q) = %+v, want an error", in, g)
		}
	}
}

// The default behaviour must be untouched. `--fail-on high` has to gate on
// severity alone, exactly as it always has, so no existing pipeline changes.
func TestGateWithoutConfidenceIsSeverityOnly(t *testing.T) {
	g, err := ParseGate("low")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []Finding{
		{Severity: SeverityLow, Confidence: 0.05},
		{Severity: SeverityCritical, Confidence: 0.10},
		{Severity: SeverityHigh, Confidence: 0},
	} {
		if !g.Passes(f) {
			t.Errorf("severity-only gate must pass %v/%v", f.Severity, f.Confidence)
		}
	}
	if g.Passes(Finding{Severity: SeverityInfo, Confidence: 1.0}) {
		t.Error("severity-only gate must still reject below-threshold severity")
	}
}

func TestGateWithConfidenceFloor(t *testing.T) {
	g, err := ParseGate("high@60%")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		sev  Severity
		conf float64
		want bool
	}{
		{SeverityHigh, 0.60, true},  // exactly at the floor passes
		{SeverityHigh, 0.59, false}, // just under does not
		{SeverityHigh, 0.85, true},
		{SeverityMedium, 0.95, false}, // confidence cannot rescue low severity
		{SeverityCritical, 0.30, false},
		{SeverityCritical, 0.95, true},
	}
	for _, tc := range cases {
		f := Finding{Severity: tc.sev, Confidence: tc.conf}
		if got := g.Passes(f); got != tc.want {
			t.Errorf("Gate(%v/%v).Passes = %v, want %v", tc.sev, tc.conf, got, tc.want)
		}
	}
}

// The reviewer's objection was that "60% confident" was displayed and then
// ignored. String must render what the user wrote so a gate is legible in CI
// logs, where the flag is the only record of what was enforced.
func TestGateString(t *testing.T) {
	for in, want := range map[string]string{
		"low":        "low",
		"high@60%":   "high@60%",
		"high@0.6":   "high@60%",
		"low@100%":   "low@100%",
		"info@0%":    "info",
		"medium@85%": "medium@85%",
	} {
		g, err := ParseGate(in)
		if err != nil {
			t.Errorf("ParseGate(%q): %v", in, err)
			continue
		}
		if got := g.String(); got != want {
			t.Errorf("ParseGate(%q).String() = %q, want %q", in, got, want)
		}
	}
}
