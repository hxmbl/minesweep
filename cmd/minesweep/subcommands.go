package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"minesweep/detectors"
	"minesweep/findings"
	"minesweep/report"
)

const configTemplate = `# MineSweep configuration
# Every option is optional - delete anything you do not need.
# Command-line flags override values in this file.

# Policy profile used to decide whether findings block, warn, or redact.
# Built-in profiles: default, developer, enterprise, public-github
profile: default

# Minimum severity that makes the scanner exit non-zero (useful as a CI gate).
# One of: info, low, medium, high, critical
fail_on: low

# Only report findings at or above this severity.
# min_severity: low

# Hide findings whose confidence is below this threshold (0.0 - 1.0).
# min_confidence: 0.5

# Only include findings tagged with one of these labels.
# tags: [aws, gcp]

# Scan test files too (they are skipped by default).
include_test_files: false

# Base branch used by "minesweep --diff" (pull-request scanning).
# diff_base: main

# Record known findings here so only NEW ones are reported later.
# Create once with: minesweep --update-baseline --baseline .minesweep-baseline.json .
# baseline_file: .minesweep-baseline.json

# Ignore specific findings listed in a suppression file.
# suppress_file: .minesweep-suppress.yml

# Directories with custom detection rules, policies, and profiles.
# On-disk directories take precedence over the built-ins shipped in the binary.
# rules_dir: rules
# policy_dir: policy
# profiles_dir: profiles

# Performance tuning (rarely needed; defaults scale with your machine).
# workers: 8
# max_files: 0              # 0 = unlimited
# max_file_size_mb: 50      # files larger than this are skipped
`

const initLongDesc = `Write a starter .minesweep.yml config file in the current directory.

The generated file documents every common option inline, so it doubles as a
reference. Existing files are never overwritten unless you pass --force.`

func newInitCommand() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a starter .minesweep.yml config file",
		Long:  initLongDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config file")
	return cmd
}

func runInit(force bool) error {
	target := ".minesweep.yml"

	if _, err := os.Stat(target); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", target)
	}
	//nolint:gosec // user-facing config file; restrictive 0600 permissions
	if err := os.WriteFile(target, []byte(configTemplate), 0600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	fmt.Printf("Created %s\n\n", target)
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the file and keep only the options you want.")
	fmt.Println("  2. Run 'minesweep .' to scan with your new settings.")
	fmt.Println("  3. Run 'minesweep install-hooks' to guard future commits.")
	return nil
}

const importIgnoreLongDesc = `Convert a .gitleaksignore file into a MineSweep suppressions file.

Both known layouts are handled:
  <commit>:<path>:<line>            (classic)
  <commit>:<path>:<rule-id>:<line>  (fingerprint style)

Each entry becomes a line-scoped suppression, so teams switching from
gitleaks keep their triage history verbatim. Unknown lines are reported
and skipped.`

func newImportIgnoresCommand() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "import-gitleaks-ignores <file>",
		Short: "Convert .gitleaksignore entries to a suppressions file",
		Long:  importIgnoreLongDesc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportIgnores(args[0], out)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", ".minesweep-suppress.json", "Output suppressions file")
	return cmd
}

// parseGitleaksIgnoreLine handles "<sha>:<path>:<line>" and
// "<sha>:<path>:<rule>:<line>". Returns nil for lines it cannot represent.
// Paths containing ':' (e.g. Windows C:\...) are handled by splitting from
// the right: the first field is always the SHA and the last field is always
// the line number.
func parseGitleaksIgnoreLine(line string) *findings.Suppression {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	// Split from the right: last field is line number, first field is SHA.
	// This correctly handles paths with ':' (Windows drive letters).
	lastColon := strings.LastIndex(line, ":")
	if lastColon < 0 {
		return nil
	}
	lineStr := strings.TrimSpace(line[lastColon+1:])
	rest := line[:lastColon]

	n, err := strconv.Atoi(lineStr)
	if err != nil || n <= 0 {
		return nil
	}

	// Now rest is "<sha>:<path>" or "<sha>:<path>:<rule>"
	firstColon := strings.Index(rest, ":")
	if firstColon < 0 {
		return nil
	}
	sha := rest[:firstColon]
	pathAndRule := rest[firstColon+1:]
	if sha == "" {
		return nil
	}

	var path, ruleID string
	// Check if there's a rule ID (3rd colon-separated field in the middle)
	// Format: <sha>:<path>:<rule>:<line>  — rule is optional
	// We know path can contain colons on Windows, so try the simple case first:
	// if there's exactly one colon in pathAndRule, it's just the path.
	// If there are more colons, we can't reliably distinguish path from rule
	// without additional context, so treat the whole thing as path.
	parts := strings.SplitN(pathAndRule, ":", 2)
	if len(parts) == 1 {
		path = parts[0]
	} else {
		// Could be <path> or <path>:<rule>. Heuristic: if parts[1] looks
		// like a rule ID (alphanumeric + hyphens, no path separators), treat
		// it as a rule. Otherwise it's part of the path.
		candidate := parts[1]
		if candidate != "" && !strings.ContainsAny(candidate, "/\\") &&
			strings.ContainsAny(candidate, "-") {
			path = parts[0]
			ruleID = candidate
		} else {
			path = pathAndRule
		}
	}

	if path == "" {
		return nil
	}

	id := fmt.Sprintf("gitleaks-%s", shortLabel(sha))
	s := &findings.Suppression{
		ID:     id,
		File:   path,
		Line:   n,
		Reason: fmt.Sprintf("imported from .gitleaksignore (%s)", sha),
	}
	if ruleID != "" {
		s.RuleID = ruleID
		s.Reason = fmt.Sprintf("imported from .gitleaksignore (commit %s)", sha)
	}
	return s
}

func shortLabel(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func runImportIgnores(in, out string) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", in, err)
	}

	list := &findings.SuppressionList{Version: "1"}
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		s := parseGitleaksIgnoreLine(raw)
		if s == nil {
			trimmed := strings.TrimSpace(raw)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				fmt.Fprintf(os.Stderr, "minesweep: warning: %s:%d: unrecognized entry %q; skipped\n", in, i+1, trimmed)
			}
			continue
		}
		list.Suppression = append(list.Suppression, *s)
	}

	if err := findings.SaveSuppressions(out, list); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}

	fmt.Printf("Converted %d entries -> %s\n\n", len(list.Suppression), out)
	fmt.Println("Use it with:")
	fmt.Printf("  minesweep --suppress %s .\n", out)
	return nil
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("minesweep %s\n", displayVersion())
			fmt.Printf("%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

const explainLongDesc = `Show what a detection rule looks for and how to respond to it.

The rule ID can be an exact ID (e.g. aws-access-key-id), a unique prefix
(e.g. aws-acc), or any unique substring. Run without arguments to list
all available rule IDs.`

func newExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "explain [rule-id]",
		Short:             "Explain a detection rule and its remediation",
		Long:              explainLongDesc,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeRuleIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			rulesList, err := loadAllRules()
			if err != nil {
				return err
			}
			if len(args) == 0 || args[0] == "" {
				listRuleIDs(rulesList)
				return nil
			}
			return explainRule(rulesList, args[0])
		},
	}
	return cmd
}

func loadAllRules() ([]detectors.Rule, error) {
	dir := cfg.RulesDir
	if dir == "" {
		dir = "rules"
	}
	det, err := detectors.NewRegexDetector(dir)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return det.Rules(), nil
}

func listRuleIDs(all []detectors.Rule) {
	ids := make([]string, 0, len(all))
	for _, r := range all {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	fmt.Printf("%d detection rules available:\n\n", len(ids))
	for _, id := range ids {
		fmt.Printf("  %s\n", id)
	}
	fmt.Println("\nRun 'minesweep explain <rule-id>' for details.")
}

func matchRules(all []detectors.Rule, query string) []detectors.Rule {
	q := strings.ToLower(query)
	var exact, prefix, substring []detectors.Rule
	for _, r := range all {
		id := strings.ToLower(r.ID)
		switch {
		case id == q:
			exact = append(exact, r)
		case strings.HasPrefix(id, q):
			prefix = append(prefix, r)
		case strings.Contains(id, q) || strings.Contains(strings.ToLower(r.Name), q):
			substring = append(substring, r)
		}
	}
	switch {
	case len(exact) > 0:
		return exact
	case len(prefix) > 0:
		return prefix
	default:
		return substring
	}
}

func explainRule(all []detectors.Rule, query string) error {
	matches := matchRules(all, query)
	switch len(matches) {
	case 1:
		printRuleDetail(matches[0])
		return nil
	case 0:
		return fmt.Errorf("no rule matches %q\n\nRun 'minesweep explain' to list all rule IDs", query)
	default:
		fmt.Printf("%d rules match %q:\n\n", len(matches), query)
		for _, m := range matches {
			fmt.Printf("  %s (%s)\n", m.ID, m.Name)
		}
		fmt.Println("\nRe-run with a longer prefix to pick one.")
		return nil
	}
}

func printRuleDetail(r detectors.Rule) {
	sev := r.Severity
	if sev == "" {
		sev = "(rule default)"
	}
	fmt.Printf("%s — %s\n", r.ID, r.Name)
	fmt.Printf("Severity: %s", sev)
	if len(r.Tags) > 0 {
		fmt.Printf(" · Tags: %s", strings.Join(r.Tags, ", "))
	}
	fmt.Println()
	if r.Description != "" {
		fmt.Printf("\nDetects: %s\n", r.Description)
	}
	if len(r.Patterns) > 0 {
		fmt.Println("\nPatterns:")
		for _, p := range r.Patterns {
			fmt.Printf("  %s", p.Regex)
			if p.Confidence > 0 {
				fmt.Printf("  (%.0f%% confident)", p.Confidence*100)
			}
			fmt.Println()
		}
	}
	if r.FileFilter != nil {
		if len(r.FileFilter.Include) > 0 {
			fmt.Printf("\nOnly scanned in files matching: %s\n", strings.Join(r.FileFilter.Include, ", "))
		}
		if len(r.FileFilter.Exclude) > 0 {
			fmt.Printf("\nSkipped in files matching: %s\n", strings.Join(r.FileFilter.Exclude, ", "))
		}
	}
	if remediation := report.RemediationText(r.ID, r.Tags); remediation != "" {
		fmt.Printf("\nWhat to do when flagged:\n  %s\n", wrapTextPlain(remediation, "  "))
	}
}

func wrapTextPlain(s, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	const width = 90
	var b strings.Builder
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line + "\n" + indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}

func completeRuleIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	all, err := loadAllRules()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, r := range all {
		if strings.HasPrefix(r.ID, toComplete) {
			out = append(out, r.ID+"\t"+r.Name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
