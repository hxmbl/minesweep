package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"minesweep/engine"
)

func TestSummarizeBenchMath(t *testing.T) {
	results := []benchRun{
		{Duration: 300 * time.Millisecond, MemBytes: 100},
		{Duration: 100 * time.Millisecond, MemBytes: 200},
		{Duration: 200 * time.Millisecond, MemBytes: 300},
	}
	s := summarizeBench("/tmp/x", results, 42, 1024, 7)

	if s.MinDur != 100*time.Millisecond {
		t.Errorf("min = %v", s.MinDur)
	}
	if s.MedDur != 200*time.Millisecond {
		t.Errorf("median = %v", s.MedDur)
	}
	if s.MaxDur != 300*time.Millisecond {
		t.Errorf("max = %v", s.MaxDur)
	}
	if s.MeanDur != 200*time.Millisecond {
		t.Errorf("mean = %v", s.MeanDur)
	}
	if s.MeanMem != 200 {
		t.Errorf("mean mem = %d, want 200", s.MeanMem)
	}
	if s.Files != 42 || s.Bytes != 1024 || s.Findings != 7 {
		t.Errorf("aggregate stats not carried through: %+v", s)
	}
}

func TestMedianDuration(t *testing.T) {
	even := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second}
	if got := medianDuration(even); got != 2500*time.Millisecond {
		t.Errorf("even median = %v", got)
	}
	if got := medianDuration(nil); got != 0 {
		t.Errorf("empty median = %v", got)
	}
}

func TestFormatHelpers(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1234, "1,234"},
		{1234567, "1,234,567"},
	}
	for _, c := range cases {
		if got := formatCount(c.in); got != c.want {
			t.Errorf("formatCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}

	if got := formatByteSize(512); got != "512 B" {
		t.Errorf("formatByteSize small = %q", got)
	}
	if got := formatByteSize(4 * 1024 * 1024); got != "4.0 MB" {
		t.Errorf("formatByteSize MB = %q", got)
	}
	if got := formatDurationShort(1500 * time.Millisecond); got != "1.50s" {
		t.Errorf("formatDurationShort sec = %q", got)
	}
	if got := formatDurationShort(250 * time.Microsecond); got != "250µs" {
		t.Errorf("formatDurationShort µs = %q", got)
	}
}

func TestWriteBenchJSONShape(t *testing.T) {
	results := []benchRun{
		{Duration: 10 * time.Millisecond, Files: 5, Bytes: 500, Findings: 1, MemBytes: 50},
		{Duration: 20 * time.Millisecond, Files: 5, Bytes: 500, Findings: 1, MemBytes: 70},
	}
	s := summarizeBench("/tmp/proj", results, 5, 500, 1)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	jsonErr := writeBenchJSON(s)
	os.Stdout = old
	w.Close()
	if jsonErr != nil {
		t.Fatalf("writeBenchJSON: %v", jsonErr)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	r.Close()

	var parsed struct {
		Benchmark bool `json:"benchmark"`
		Path      string
		Runs      int
		Files     int
		Bytes     int64
		Findings  int
		TimesMs   struct {
			Min    float64
			Median float64
			Mean   float64
			Max    float64
		} `json:"times_ms"`
		MeanMemoryByte int64
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if !parsed.Benchmark || parsed.Runs != 2 || parsed.Files != 5 || parsed.Findings != 1 {
		t.Errorf("unexpected fields: %+v", parsed)
	}
	if parsed.TimesMs.Min <= 0 || parsed.TimesMs.Max < parsed.TimesMs.Min {
		t.Errorf("implausible times: %+v", parsed.TimesMs)
	}
}

func TestRunBenchmarkEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello world\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg = engine.Config{}
	if err := runBenchmark(dir, false, 2); err != nil {
		t.Fatalf("runBenchmark text mode: %v", err)
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		old := os.Stdout
		os.Stdout = devnull
		err = runBenchmark(dir, true, 2)
		os.Stdout = old
		devnull.Close()
		if err != nil {
			t.Fatalf("runBenchmark json mode: %v", err)
		}
	}
}

func TestBenchTextOutputContainsKeyStats(t *testing.T) {
	results := []benchRun{{Duration: 5 * time.Millisecond}}
	s := summarizeBench("/some/path", results, 12, 4096, 3)

	var buf bytes.Buffer
	stdout := os.Stdout
	rp, wp, _ := os.Pipe()
	os.Stdout = wp
	writeBenchText(s)
	wp.Close()
	os.Stdout = stdout
	buf.ReadFrom(rp)

	out := buf.String()
	for _, want := range []string{"MineSweep Benchmark", "/some/path", "Files:", "Scan times:", "Throughput"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
