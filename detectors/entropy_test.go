package detectors

import (
	"math"
	"testing"

	"minesweep/filesystem"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{"empty", "", 0, 0},
		{"single_char", "aaaa", 0, 0.01},
		{"low_entropy", "aaaaaaaaaa", 0, 0.5},
		{"medium_entropy", "abcdefghij", 2.5, 3.5},
		{"high_entropy", "a1b2c3d4e5f6g7h8", 3.5, 4.5},
		{"very_high_entropy", "xK9#mP2$vL8@nQ4w", 3.5, 4.5},
		{"hex_string", "0123456789abcdef", 3.5, 4.0},
		{"base64_like", "SGVsbG8gV29ybGQh", 3.0, 4.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %v, want [%v, %v]", tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestShannonEntropyUniform(t *testing.T) {
	got := shannonEntropy("abc")
	expected := math.Log2(3)
	if math.Abs(got-expected) > 0.001 {
		t.Errorf("shannonEntropy(\"abc\") = %v, want %v", got, expected)
	}
}

func TestEntropyDetectorHighEntropy(t *testing.T) {
	d := NewEntropyDetector()

	// Use a string with only characters matching extractStringsRe: [A-Za-z0-9\-_+=/]
	longHigh := "aB3dE5gH7jK9mN1pQ3sT5vW8yA2cE4fG6hI0kL2mN4"
	content := "normal config value\n" + longHigh + "\nanother normal line\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}
	results := d.Detect(file)
	if len(results) == 0 {
		t.Fatal("expected high-entropy string to be detected")
	}
	found := false
	for _, f := range results {
		if f.Value == longHigh {
			found = true
			if f.Confidence < scoreMinConfidence {
				t.Errorf("confidence %v below threshold", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected to find specific high-entropy string")
	}
}

func TestEntropyDetectorLowEntropyIgnored(t *testing.T) {
	d := NewEntropyDetector()

	content := "hello world\nfoo bar baz\nthis is normal text\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}
	results := d.Detect(file)
	for _, f := range results {
		if f.Confidence >= 0.5 {
			t.Errorf("unexpected high-confidence finding: %s (confidence=%.2f)", f.Value, f.Confidence)
		}
	}
}

func TestEntropyDetectorShortStringsSkipped(t *testing.T) {
	d := NewEntropyDetector()

	content := "a\nbb\nccc\ndddd\neeeee\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}
	results := d.Detect(file)
	for _, f := range results {
		if len(f.Value) < entropyMinWordLength {
			t.Errorf("expected min length %d, got %d: %q", entropyMinWordLength, len(f.Value), f.Value)
		}
	}
}

func TestEntropyDetectorBinarySafe(t *testing.T) {
	d := NewEntropyDetector()

	longHigh := "xK9#mP2$vL8@nQ4wR9tY2uI3oP4aS5dF"
	content := "safe line\n" + longHigh + "\nsafe line\n"
	file := &filesystem.File{
		Path:     "test.txt",
		Content:  []byte(content),
		IsBinary: true,
	}
	results := d.Detect(file)
	if len(results) != 0 {
		t.Error("expected 0 findings for binary file")
	}
}

func TestEntropyDetectorLineNumbers(t *testing.T) {
	d := NewEntropyDetector()

	longHigh := "aB3dE5gH7jK9mN1pQ3sT5vW8yA2cE4fG6hI0kL2mN4"
	content := "safe\nsafe\n" + longHigh + "\nsafe\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}
	results := d.Detect(file)

	for _, f := range results {
		if f.Value == longHigh {
			if f.Line != 3 {
				t.Errorf("expected line 3, got %d", f.Line)
			}
			return
		}
	}
	t.Fatal("expected to find high-entropy string on line 3")
}

func TestEntropyDetectorKeywordBoost(t *testing.T) {
	d := NewEntropyDetector()

	longHigh := "aB3dE5gH7jK9mN1pQ3sT5vW8yA2cE4fG6hI0kL2mN4"
	content := "api_key " + longHigh + "\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}

	resultsWithKeyword := d.Detect(file)

	contentNoKeyword := "value " + longHigh + "\n"
	fileNoKeyword := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(contentNoKeyword),
	}
	resultsNoKeyword := d.Detect(fileNoKeyword)

	if len(resultsWithKeyword) == 0 || len(resultsNoKeyword) == 0 {
		t.Fatalf("expected findings in both cases: keyword=%d no-keyword=%d", len(resultsWithKeyword), len(resultsNoKeyword))
	}

	var confKeyword, confNoKeyword float64
	for _, f := range resultsWithKeyword {
		if f.Value == longHigh {
			confKeyword = f.Confidence
		}
	}
	for _, f := range resultsNoKeyword {
		if f.Value == longHigh {
			confNoKeyword = f.Confidence
		}
	}

	if confKeyword <= confNoKeyword {
		t.Errorf("expected keyword match to boost confidence: with=%v without=%v", confKeyword, confNoKeyword)
	}
}

func TestEntropyDetectorSourceLine(t *testing.T) {
	d := NewEntropyDetector()

	longHigh := "aB3dE5gH7jK9mN1pQ3sT5vW8yA2cE4fG6hI0kL2mN4"
	content := "token " + longHigh + "\n"
	file := &filesystem.File{
		Path:    "test.txt",
		Content: []byte(content),
	}
	results := d.Detect(file)
	for _, f := range results {
		if f.Value == longHigh {
			if f.SourceLine != "token "+longHigh {
				t.Errorf("expected source line 'token ...', got %q", f.SourceLine)
			}
			return
		}
	}
}
