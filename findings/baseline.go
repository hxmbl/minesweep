package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/zeebo/blake3"
)

const currentFingerprintPrefix = "b3:"

// historyDisplaySuffix matches the "@sha12" suffix history mode appends to
// file paths. Baselines must be namespace-agnostic: a working-tree baseline
// entry has to match the same secret discovered through --history.
var historyDisplaySuffix = regexp.MustCompile(`@[0-9a-f]{12}$`)

func normalizeBaselineFile(file string) string {
	return historyDisplaySuffix.ReplaceAllString(file, "")
}

type Baseline struct {
	Version  string                   `json:"version"`
	Findings map[string]BaselineEntry `json:"findings"`
}

// BaselineEntry is the on-disk record for an accepted finding. It never
// stores the raw secret: the map key binds the value with a full BLAKE3
// fingerprint, and ValueToken keeps only a truncated digest so value-less
// entries can still be recognised. Baseline files are routinely committed,
// so writing a live credential into one would defeat the point of the tool.
type BaselineEntry struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	RuleID     string `json:"rule_id"`
	ValueToken string `json:"value_token,omitempty"`

	// Triage provenance: why the finding was accepted, and by whom/when.
	Reason string `json:"reason,omitempty"`
	Author string `json:"author,omitempty"`
	Date   string `json:"date,omitempty"`
}

// UnmarshalJSON keeps old baselines (where each finding mapped to a location
// string) readable, converting them to the entry form. Old entries had their
// value bound into the fingerprint but recorded no metadata; they are not
// mistaken for value-less entries because their keys lack the b3: prefix.
func (b *Baseline) UnmarshalJSON(data []byte) error {
	type raw struct {
		Version  string                     `json:"version"`
		Findings map[string]json.RawMessage `json:"findings"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	b.Version = r.Version
	b.Findings = make(map[string]BaselineEntry, len(r.Findings))
	for k, v := range r.Findings {
		var loc string
		if err := json.Unmarshal(v, &loc); err == nil {
			entry := BaselineEntry{}
			parts := splitLocation(loc)
			if len(parts) > 0 {
				entry.File = parts[0]
			}
			if len(parts) > 1 {
				// Best effort; ignore parse errors.
				n := 0
				fmt.Sscanf(parts[1], "%d", &n)
				entry.Line = n
			}
			b.Findings[k] = entry
			continue
		}
		var e BaselineEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return fmt.Errorf("parse baseline entry %s: %w", k, err)
		}
		b.Findings[k] = e
	}
	return nil
}

// valueToken is a non-reversible marker used only to tell whether a value was
// present when the entry was baselined. The full value lives solely in the
// fingerprint; this token is safe to write to a shared baseline file.
func valueToken(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// valueLess reports whether entry was baselined without a value, which means
// it suppresses its rule at that location for any content. Legacy entries
// bound their value into a SHA-256 fingerprint, so they never qualify.
func valueLess(hash string, entry BaselineEntry) bool {
	return strings.HasPrefix(hash, currentFingerprintPrefix) && entry.ValueToken == "" && entry.RuleID != ""
}

func LoadBaseline(path string) (*Baseline, error) {
	// Reading a path the caller named is the whole purpose of this function.
	data, err := os.ReadFile(path) //nolint:gosec // caller-specified baseline path
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{
				Version:  "1",
				Findings: make(map[string]BaselineEntry),
			}, nil
		}
		return nil, fmt.Errorf("read baseline file: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline file: %w", err)
	}

	if b.Findings == nil {
		b.Findings = make(map[string]BaselineEntry)
	}
	for _, w := range BaselineWarnings(&b) {
		fmt.Fprintf(os.Stderr, "minesweep: warning: %s\n", w)
	}
	return &b, nil
}

func SaveBaseline(path string, b *Baseline) error {
	if b.Findings == nil {
		b.Findings = make(map[string]BaselineEntry)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644) //nolint:gosec // standard permissions for CLI output
}

// findingHashInput is separate from BaselineEntry so the fingerprint keeps
// its original field order and shape even as the on-disk entry gains metadata.
// Changing the JSON here would silently invalidate existing baselines.
type findingHashInput struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	RuleID string `json:"rule_id"`
	Value  string `json:"value,omitempty"`
}

func FindingHash(f Finding) string {
	return currentFingerprintPrefix + findingHash(f, blake3.Sum256)
}

func findingHash(f Finding, hash func([]byte) [32]byte) string {
	entry := findingHashInput{
		File:   normalizeBaselineFile(f.File),
		Line:   f.Line,
		RuleID: f.RuleID,
		Value:  f.Value,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	sum := hash(data)
	return fmt.Sprintf("%x", sum)
}

func legacyFindingHash(f Finding) string { return findingHash(f, sha256.Sum256) }

func FilterNewFindings(findings []Finding, baseline *Baseline) []Finding {
	if baseline == nil {
		return findings
	}

	var newFindings []Finding
	for _, f := range findings {
		hash := FindingHash(f)
		if _, exists := baseline.Findings[hash]; exists {
			continue
		}
		if _, exists := baseline.Findings[legacyFindingHash(f)]; exists {
			continue
		}
		// A value-less entry suppresses its rule at that location regardless
		// of the secret now found there. It is warned about on load, but the
		// suppression is real and must stay consistent with prune().
		suppressed := false
		for hash, entry := range baseline.Findings {
			if valueLess(hash, entry) &&
				entry.File == normalizeBaselineFile(f.File) &&
				entry.Line == f.Line &&
				entry.RuleID == f.RuleID {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}
		newFindings = append(newFindings, f)
	}
	return newFindings
}

func UpdateBaseline(baseline *Baseline, findings []Finding) {
	if baseline.Findings == nil {
		baseline.Findings = make(map[string]BaselineEntry)
	}
	for _, f := range findings {
		hash := FindingHash(f)
		entry := BaselineEntry{
			File:       normalizeBaselineFile(f.File),
			Line:       f.Line,
			RuleID:     f.RuleID,
			ValueToken: valueToken(f.Value),
		}
		if existing, ok := baseline.Findings[hash]; ok {
			// Regeneration must not forget why a finding was accepted.
			entry.Reason = existing.Reason
			entry.Author = existing.Author
			entry.Date = existing.Date
		}
		if entry.ValueToken == "" {
			fmt.Fprintf(os.Stderr, "minesweep: warning: baselining %s:%d (%s) without a recorded value; this suppresses the rule for any content at that path\n",
				entry.File, entry.Line, entry.RuleID)
		}
		baseline.Findings[hash] = entry
	}
}

func GetBaselineStats(baseline *Baseline) (total int, files []string) {
	if baseline == nil {
		return 0, nil
	}

	fileSet := make(map[string]bool)
	for _, entry := range baseline.Findings {
		if entry.File != "" {
			fileSet[entry.File] = true
		}
	}

	for f := range fileSet {
		files = append(files, f)
	}
	sort.Strings(files)
	return len(baseline.Findings), files
}

func splitLocation(s string) []string {
	// Split on the last colon to handle Windows paths (e.g. C:\path\file:123).
	// The stored format is always "file:line" where line is numeric.
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}

// BaselineWarnings reports problems with baseline entries, such as value-less
// entries that suppress a rule for any content at their path.
func BaselineWarnings(b *Baseline) []string {
	if b == nil {
		return nil
	}
	var out []string
	for hash, entry := range b.Findings {
		if valueLess(hash, entry) {
			out = append(out, fmt.Sprintf("baseline entry %s (%s:%d) suppresses rule %q without a recorded value", hash, entry.File, entry.Line, entry.RuleID))
		}
	}
	sort.Strings(out)
	return out
}

// PruneBaseline removes baseline entries that no longer correspond to a current
// finding. It returns the removed entries and mutates the baseline in place.
func PruneBaseline(baseline *Baseline, findings []Finding) []BaselineEntry {
	if baseline == nil || baseline.Findings == nil {
		return nil
	}

	var removed []BaselineEntry
	for hash, entry := range baseline.Findings {
		matched := false
		for _, f := range findings {
			if FindingHash(f) == hash || legacyFindingHash(f) == hash {
				matched = true
				break
			}
			if valueLess(hash, entry) &&
				entry.File == normalizeBaselineFile(f.File) &&
				entry.Line == f.Line &&
				entry.RuleID == f.RuleID {
				matched = true
				break
			}
		}
		if !matched {
			removed = append(removed, entry)
			delete(baseline.Findings, hash)
		}
	}
	sort.Slice(removed, func(i, j int) bool {
		if removed[i].File != removed[j].File {
			return removed[i].File < removed[j].File
		}
		if removed[i].Line != removed[j].Line {
			return removed[i].Line < removed[j].Line
		}
		return removed[i].RuleID < removed[j].RuleID
	})
	return removed
}

// PruneReason explains why an entry was pruned, so prune output can say more
// than "no match": line drift and a changed value are different signals.
func PruneReason(entry BaselineEntry, findings []Finding) string {
	fileSeen, lineSeen, ruleSeen := false, false, false
	for _, f := range findings {
		if normalizeBaselineFile(f.File) != entry.File {
			continue
		}
		fileSeen = true
		if f.Line != entry.Line {
			continue
		}
		lineSeen = true
		if f.RuleID == entry.RuleID {
			ruleSeen = true
		}
	}
	switch {
	case !fileSeen:
		return "file no longer has findings"
	case !lineSeen:
		return "line moved"
	case !ruleSeen:
		return "rule no longer reports at this location"
	default:
		return "value changed"
	}
}
