package main

import (
	"os"
	"testing"

	"minesweep/findings"
	"minesweep/report"
)

func TestResolvePagerCommandPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		expected string
	}{
		{"default when nothing set", map[string]string{}, defaultPager},
		{"MINESWEEP_PAGER wins", map[string]string{"MINESWEEP_PAGER": "moar -x", "PAGER": "cat"}, "moar -x"},
		{"GIT_PAGER second", map[string]string{"GIT_PAGER": "delta", "PAGER": "cat"}, "delta"},
		{"PAGER third", map[string]string{"PAGER": "more"}, "more"},
		{"empty values fall through", map[string]string{"MINESWEEP_PAGER": "  ", "PAGER": "cat"}, "cat"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"MINESWEEP_PAGER", "GIT_PAGER", "PAGER"} {
				os.Unsetenv(k)
			}
			for k, v := range c.env {
				os.Setenv(k, v)
			}
			defer func() {
				for _, k := range []string{"MINESWEEP_PAGER", "GIT_PAGER", "PAGER"} {
					os.Unsetenv(k)
				}
			}()
			if got := resolvePagerCommand(); got != c.expected {
				t.Errorf("resolvePagerCommand() = %q, want %q", got, c.expected)
			}
		})
	}
}

func TestShouldPageDecisionMatrix(t *testing.T) {
	origNoPager := noPager
	defer func() { noPager = origNoPager }()

	cases := []struct {
		name    string
		tty     bool
		noPager bool
		env     string
		watch   bool
		want    bool
	}{
		{"interactive human", true, false, "", false, true},
		{"piped output never pages", false, false, "", false, false},
		{"--no-pager opt-out", true, true, "", false, false},
		{"env opt-out", true, false, "1", false, false},
		{"watch mode never pages", true, false, "", true, false},
		{"env false value does not block", true, false, "false", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			noPager = c.noPager
			watchMode = c.watch
			os.Unsetenv("MINESWEEP_NO_PAGER")
			if c.env != "" {
				os.Setenv("MINESWEEP_NO_PAGER", c.env)
				defer os.Unsetenv("MINESWEEP_NO_PAGER")
			}
			if got := shouldPage(c.tty); got != c.want {
				t.Errorf("shouldPage(%v) with noPager=%v env=%q watch=%v = %v, want %v",
					c.tty, c.noPager, c.env, c.watch, got, c.want)
			}
		})
	}
	watchMode = false
}

func TestRenderFallsBackWhenPagerMissing(t *testing.T) {
	origNoPager := noPager
	watchOrig := watchMode
	noPager, watchMode = false, false
	defer func() { noPager, watchMode = origNoPager, watchOrig }()

	os.Setenv("MINESWEEP_PAGER", "/definitely/not/a/real/binary-xyz")
	defer os.Unsetenv("MINESWEEP_PAGER")

	ttyOrig := stdoutIsTTYFn
	stdoutIsTTYFn = func() bool { return true }
	defer func() { stdoutIsTTYFn = ttyOrig }()

	rep := findings.GenerateRiskReport([]findings.Finding{
		{Type: "T", RuleID: "t-rule", Severity: findings.SeverityHigh, File: "a.go", Line: 1},
	}, nil)
	opts := &report.TextOptions{}

	if err := renderTextInteractive(&rep, opts); err != nil {
		t.Fatalf("missing pager should fall back gracefully: %v", err)
	}
}
