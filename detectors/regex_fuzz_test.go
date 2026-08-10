// +build gofuzz

package detectors

import (
	"minesweep/filesystem"
)

// FuzzRuleParsing fuzzes the YAML rule parsing to find edge cases
func FuzzRuleParsing(f *testing.F) {
	// Seed corpus with valid rule examples
	f.Add([]byte(`rules:
  - id: test
    type: regex
    name: Test
    patterns:
      - regex: test`))
	f.Add([]byte(`rules:
  - id: test2
    type: regex
    name: Test2
    severity: high
    patterns:
      - regex: [a-z]+`))
	f.Add([]byte(`rules: []`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`rules:
  - id: test
    type: regex
    name: Test
    patterns:
      - regex: (a+)+$`)) // ReDoS pattern

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse as a rule file
		var rf RuleFile
		err := yaml.Unmarshal(data, &rf)
		if err != nil {
			// Expected for invalid input
			return
		}
		
		// Try to compile all patterns
		for i := range rf.Rules {
			for j := range rf.Rules[i].Patterns {
				// This should not panic
				_ = rf.Rules[i].Patterns[j].compile()
			}
		}
	})
}

// FuzzRegexMatching fuzzes regex matching with various inputs
func FuzzRegexMatching(f *testing.F) {
	// Create a simple detector with a safe pattern
	d, err := NewRegexDetector("rules")
	if err != nil {
		// If we can't load rules, skip this test
		return
	}

	// Seed corpus
	f.Add([]byte("safe content"))
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"))
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte(strings.Repeat("a", 1000)))

	f.Fuzz(func(t *testing.T, content []byte) {
		// Create a file with the content
		file := &filesystem.File{
			Path:    "test.txt",
			Content: content,
			Size:    int64(len(content)),
			Mode:    0644,
		}
		
		// This should not panic or hang
		findings := d.Detect(file)
		// We don't care about the results, just that it doesn't crash
		_ = findings
	})
}
