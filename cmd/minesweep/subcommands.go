package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"minesweep/detectors"
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
	if err := os.WriteFile(target, []byte(configTemplate), 0644); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	fmt.Printf("Created %s\n\n", target)
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the file and keep only the options you want.")
	fmt.Println("  2. Run 'minesweep .' to scan with your new settings.")
	fmt.Println("  3. Run 'minesweep install-hooks' to guard future commits.")
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
