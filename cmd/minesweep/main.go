package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"minesweep/config"
	"minesweep/engine"
	"minesweep/filesystem"
	"minesweep/findings"
	"minesweep/git"
	"minesweep/report"
)

// exitCodeError carries a process exit code through cobra's error chain
// so that deferred functions run and cobra can clean up before the process exits.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

var (
	cfg             engine.Config
	outputJSON      bool
	outputSARIF     bool
	outputDashboard bool
	showAnnotations bool
	showSnippets    bool
	colorMode       string
	benchMode       bool
	benchRuns       int
	noPager         bool
	// toolVersion is stamped at build time via
	// -ldflags "-X main.toolVersion=x.y.z".
	// It must NOT have a package-level constant initializer, otherwise the
	// compiler folds the value into call sites and -X silently no-ops.
	toolVersion string
	configPath  string
	// hookForce allows install-hooks to replace a third-party hook.
	hookForce     bool
	watchMode     bool
	watchInterval time.Duration
)

const rootLongDesc = `MineSweep scans files for secrets, credentials, and sensitive data,
evaluates them against policies, and produces a risk report.

Quickstart:
  minesweep .                    scan the current directory (sensible defaults)
  minesweep -p developer .       relaxed policy for local development
  minesweep init                 create a starter config file
  minesweep install-hooks        block secrets before every commit
  minesweep explain <rule-id>    learn what a rule detects and how to respond

Typical workflows:
  CI gate ............ minesweep --fail-on high .
  Pull request ....... minesweep --diff --diff-base main .
  SARIF for GitHub ... minesweep --sarif . > results.sarif
  Known findings ..... minesweep --update-baseline --baseline .ms-baseline.json .

Exit codes: 0 = clean (or below --fail-on), 1 = findings at or above threshold.`

func main() {
	root := &cobra.Command{
		Use:           "minesweep [path]",
		Short:         "MineSweep - policy engine for secrets and sensitive data",
		Long:          rootLongDesc,
		Args:          cobra.ExactArgs(1),
		Version:       displayVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "install-hooks" || cmd.Name() == "uninstall-hooks" ||
				cmd.Name() == "init" || cmd.Name() == "version" || cmd.Name() == "explain" ||
				cmd.Name() == "import-gitleaks-ignores" {
				return nil
			}
			if cfg.FailOn != "" && !findings.IsValidSeverity(cfg.FailOn) {
				return fmt.Errorf("invalid --fail-on value %q (valid: info, low, medium, high, critical)", cfg.FailOn)
			}
			if cfg.MinSeverity != "" && !findings.IsValidSeverity(cfg.MinSeverity) {
				return fmt.Errorf("invalid --min-severity value %q (valid: info, low, medium, high, critical)", cfg.MinSeverity)
			}
			if cfg.HistoryMode && (cfg.DiffMode || cfg.StagedOnly) {
				return fmt.Errorf("--history scans all refs and cannot be combined with --diff or --staged")
			}
			if err := validateNumericFlags(cmd, cfg); err != nil {
				return err
			}
			// An explicitly requested rules path must exist. Without this a typo
			// in --rules, or a file passed where a directory was meant, silently
			// produced a scan using only the embedded rules: the user got fewer
			// detections and no indication why.
			if cmd.Flags().Changed("rules") && cfg.RulesDir != "" {
				if _, statErr := os.Stat(cfg.RulesDir); statErr != nil {
					return fmt.Errorf("--rules %q: %w", cfg.RulesDir, statErr)
				}
			}
			return loadConfig(cmd, args[0])
		},
		RunE: runScan,
	}

	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprint(cmd.OutOrStdout(), renderGroupedHelp(cmd)) //nolint:errcheck // best-effort help; the exit code is what matters
	})

	// --rules is persistent so subcommands like `explain` resolve the same
	// rule directory (disk dir, embedded fallback) as scans do.
	root.PersistentFlags().StringVarP(&cfg.RulesDir, "rules", "r", "rules", "Directory containing rule YAML files")
	root.Flags().StringVarP(&cfg.PolicyFile, "policy", "", "", "Policy file to evaluate against")
	root.Flags().StringVarP(&cfg.Profile, "profile", "p", "", "Profile name (developer, enterprise, public-github)")
	root.Flags().StringVarP(&cfg.ProfilesDir, "profiles", "", "profiles", "Directory containing profile YAML files")
	root.Flags().BoolVarP(&outputJSON, "json", "", false, "Output as JSON")
	root.Flags().BoolVarP(&outputSARIF, "sarif", "", false, "Output as SARIF (for CI/CD)")
	root.Flags().BoolVarP(&outputDashboard, "dashboard", "", false, "Show rule health dashboard")
	root.Flags().BoolVarP(&showAnnotations, "annotations", "", false, "Show GitHub Actions annotations")
	root.Flags().BoolVarP(&showSnippets, "snippets", "", false, "Show code snippets with censored sensitive values")
	root.Flags().StringVarP(&colorMode, "color", "", "auto", "When to colorize output: auto, always, never")
	root.Flags().BoolVarP(&noPager, "no-pager", "", false, "Print text reports directly instead of paging")
	root.Flags().BoolVarP(&benchMode, "benchmark", "", false, "Time full scans instead of writing a report")
	root.Flags().IntVarP(&benchRuns, "runs", "", 1, "Number of timed runs for --benchmark (min/median/mean/max reported)")
	root.Flags().StringVarP(&cfg.PolicyDir, "policy-dir", "", "policy", "Directory containing policy YAML files")
	root.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
	root.Flags().StringVarP(&cfg.FailOn, "fail-on", "", "low", "Minimum severity that exits non-zero (info, low, medium, high, critical)")
	root.Flags().Float64VarP(&cfg.MinConfidence, "min-confidence", "", 0, "Minimum confidence threshold to include findings (0.0-1.0)")
	root.Flags().StringVarP(&cfg.MinSeverity, "min-severity", "", "", "Minimum severity to report (info, low, medium, high, critical)")
	root.Flags().StringArrayVarP(&cfg.Tags, "tag", "t", nil, "Filter by tag (can be specified multiple times)")
	root.Flags().BoolVarP(&cfg.DiffMode, "diff", "d", false, "Only scan files changed vs base branch")
	root.Flags().BoolVarP(&cfg.HistoryMode, "history", "H", false, "Scan every unique blob across all git history")
	root.Flags().StringVarP(&cfg.DiffBase, "diff-base", "", "main", "Base branch for diff comparison")
	root.Flags().BoolVarP(&cfg.StagedOnly, "staged", "s", false, "Only scan git staged files")
	root.Flags().StringVarP(&cfg.BaselineFile, "baseline", "b", "", "Baseline file to compare against (only report new findings)")
	root.Flags().BoolVarP(&cfg.UpdateBaseline, "update-baseline", "", false, "Update baseline file with current findings")
	root.Flags().IntVarP(&cfg.Workers, "workers", "w", 0, "Number of concurrent workers (default: NumCPU)")
	root.Flags().StringVar(&configPath, "config", "", "Path to config file (default: search for .minesweep.yml)")
	root.Flags().StringVarP(&cfg.SuppressFile, "suppress", "", "", "Suppression file to ignore specific findings")
	root.Flags().BoolVarP(&cfg.IncludeTestFiles, "include-tests", "", false, "Include test files in scan (skipped by default)")
	root.Flags().BoolVarP(&watchMode, "watch", "", false, "Watch for file changes and re-scan automatically")
	root.Flags().DurationVarP(&watchInterval, "watch-interval", "", 2*time.Second, "How often to check for changes in watch mode")
	root.Flags().IntVarP(&cfg.MaxFiles, "max-files", "", 0, "Maximum number of files to scan (0 = unlimited)")
	root.Flags().IntVarP(&cfg.MemoryLimitMB, "memory-limit-mb", "", 0, "Maximum memory usage in MB (0 = unlimited)")
	root.Flags().Int64VarP(&cfg.MaxFileSizeMB, "max-file-size-mb", "", 0, "Maximum file size in MB to scan (0 = use default)")
	root.Flags().IntVarP(&cfg.MaxConcurrentReads, "max-concurrent-reads", "", 0, "Maximum concurrent file reads (0 = use workers)")
	root.Flags().IntVar(&cfg.MaxFindings, "max-findings", engine.DefaultMaxFindings, "Maximum findings to report; highest-confidence kept when exceeded (0 = unlimited)")
	root.Flags().BoolVar(&cfg.NoIgnore, "no-ignore", false, "Scan everything, ignoring .minesweepignore and .msignore")
	root.Flags().BoolVar(&cfg.ShowIgnored, "show-ignored", false, "List every skipped file path (default: sample per cause)")
	root.Flags().BoolVar(&cfg.IncludeLowConfidence, "include-low-confidence", false, "Report findings below the default confidence floor")
	root.Flags().BoolVar(&cfg.DisableInlineSuppression, "no-inline-suppressions", false,
		"Ignore 'minesweep: ignore' comments in scanned files (use in CI to stop content suppressing itself)")
	root.Flags().BoolVar(&cfg.DangerouslyShowSecrets, "dangerously-show-secrets", false, "Print raw secret values instead of hashes")

	installHooks := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install git pre-commit hook",
		Long: "Install a pre-commit hook that runs minesweep on staged files.\n\n" +
			"An existing hook that minesweep did not install is never overwritten\n" +
			"unless --force is given; with --force the original is backed up first.",
		RunE: runInstallHooks,
	}
	installHooks.Flags().BoolVar(&hookForce, "force", false,
		"Replace an existing pre-commit hook that minesweep did not install")
	root.AddCommand(installHooks)

	root.AddCommand(&cobra.Command{
		Use:   "uninstall-hooks",
		Short: "Remove git pre-commit hook",
		RunE:  runUninstallHooks,
	})

	root.AddCommand(newInitCommand())
	root.AddCommand(newVersionCommand())
	root.AddCommand(newExplainCommand())
	root.AddCommand(newImportIgnoresCommand())

	if err := root.Execute(); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		fmt.Fprintf(os.Stderr, "%s %v\n", "error:", err)
		fmt.Fprintf(os.Stderr, "\nRun 'minesweep --help' to see all commands and options.\n")
		os.Exit(1)
	}
}

// configField describes one config-file key: how to detect its presence,
// apply it, and whether it can weaken detection when sourced from an
// auto-discovered (untrusted) .minesweep.yml.
type configField struct {
	label   string
	flag    string // cobra flag name; empty = no CLI flag exists
	secure  bool   // requires explicit trust (--config / CLI flag) when discovered
	isPath  bool   // resolved relative to the config file's directory
	apply   func(cfg *engine.Config, fc *config.FileConfig, dir string)
	present func(fc *config.FileConfig) bool
}

func strField(label, flag string, secure bool,
	get func(*config.FileConfig) string,
	set func(*engine.Config, string),
	present func(*config.FileConfig) bool,
) configField {
	return configField{label: label, flag: flag, secure: secure,
		apply:   func(cfg *engine.Config, fc *config.FileConfig, _ string) { set(cfg, get(fc)) },
		present: present}
}

func numField(label, flag string, secure bool,
	get func(*config.FileConfig) string,
	apply func(*engine.Config, string),
	present func(*config.FileConfig) bool,
) configField {
	return configField{label: label, flag: flag, secure: secure,
		apply:   func(cfg *engine.Config, fc *config.FileConfig, _ string) { apply(cfg, get(fc)) },
		present: present}
}

var configFields = []configField{
	// ---- safe: performance / verbosity only ----
	strField("verbose", "verbose", false,
		func(f *config.FileConfig) string {
			if f.Verbose {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.Verbose = v == "true" },
		func(f *config.FileConfig) bool { return f.Verbose }),
	numField("workers", "workers", false,
		func(f *config.FileConfig) string {
			if f.Workers > 0 {
				return fmt.Sprint(f.Workers)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%d", &c.Workers) },
		func(f *config.FileConfig) bool { return f.Workers > 0 }),
	numField("max_files", "max-files", true,
		func(f *config.FileConfig) string {
			if f.MaxFiles > 0 {
				return fmt.Sprint(f.MaxFiles)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%d", &c.MaxFiles) },
		func(f *config.FileConfig) bool { return f.MaxFiles > 0 }),
	numField("max_findings", "max-findings", true,
		func(f *config.FileConfig) string {
			if f.MaxFindings > 0 {
				return fmt.Sprint(f.MaxFindings)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%d", &c.MaxFindings) },
		func(f *config.FileConfig) bool { return f.MaxFindings > 0 }),
	numField("memory_limit_mb", "memory-limit-mb", true,
		func(f *config.FileConfig) string {
			if f.MemoryLimitMB > 0 {
				return fmt.Sprint(f.MemoryLimitMB)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%d", &c.MemoryLimitMB) },
		func(f *config.FileConfig) bool { return f.MemoryLimitMB > 0 }),
	numField("max_file_size_mb", "max-file-size-mb", true,
		func(f *config.FileConfig) string {
			if f.MaxFileSizeMB > 0 {
				return fmt.Sprint(f.MaxFileSizeMB)
			}
			return ""
		},
		func(c *engine.Config, v string) {
			var n int64
			_, _ = fmt.Sscanf(v, "%d", &n)
			c.MaxFileSizeMB = n
		},
		func(f *config.FileConfig) bool { return f.MaxFileSizeMB > 0 }),
	numField("max_concurrent_reads", "max-concurrent-reads", true,
		func(f *config.FileConfig) string {
			if f.MaxConcurrentReads > 0 {
				return fmt.Sprint(f.MaxConcurrentReads)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%d", &c.MaxConcurrentReads) },
		func(f *config.FileConfig) bool { return f.MaxConcurrentReads > 0 }),

	// ---- security-relevant: ignored from discovered configs ----
	//
	// Everything here either removes coverage, weakens a gate, or decides what
	// counts as a finding. A config file found by walking up from the scan
	// target is, by construction, supplied by whatever is being scanned, so it
	// may not be allowed to reduce what the scan looks at. That includes the
	// resource limits: max_file_size_mb was previously classed as a
	// performance knob, and a repository could ship `max_file_size_mb: 1` and
	// have every file holding a credential skipped while the scan still
	// reported "No secrets" and exited 0.
	strField("no_ignore", "no-ignore", true,
		func(f *config.FileConfig) string {
			if f.NoIgnore {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.NoIgnore = v == "true" },
		func(f *config.FileConfig) bool { return f.NoIgnore }),
	strField("include_low_confidence", "include-low-confidence", false,
		func(f *config.FileConfig) string {
			if f.IncludeLowConfidence {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.IncludeLowConfidence = v == "true" },
		func(f *config.FileConfig) bool { return f.IncludeLowConfidence }),
	// Disabling inline suppression only ever surfaces MORE findings, so an
	// untrusted config may set it. Suppression itself is never enabled from a
	// config file: there is no way to grant a repository the power to silence
	// its own findings.
	strField("no_inline_suppressions", "no-inline-suppressions", false,
		func(f *config.FileConfig) string {
			if f.NoInlineSuppressions {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.DisableInlineSuppression = v == "true" },
		func(f *config.FileConfig) bool { return f.NoInlineSuppressions }),
	// Intentionally has no config-file entry: raw secret values must be
	// opted into on the command line, never by a file in the repository.
	pathField("rules_dir", "rules", func(c *engine.Config, v string) { c.RulesDir = v }, func(f *config.FileConfig) bool { return f.RulesDir != "" }),
	pathField("profiles_dir", "profiles", func(c *engine.Config, v string) { c.ProfilesDir = v }, func(f *config.FileConfig) bool { return f.ProfilesDir != "" }),
	pathField("policy_dir", "policy-dir", func(c *engine.Config, v string) { c.PolicyDir = v }, func(f *config.FileConfig) bool { return f.PolicyDir != "" }),
	pathField("policy_file", "policy", func(c *engine.Config, v string) { c.PolicyFile = v }, func(f *config.FileConfig) bool { return f.PolicyFile != "" }),
	pathField("baseline_file", "baseline", func(c *engine.Config, v string) { c.BaselineFile = v }, func(f *config.FileConfig) bool { return f.BaselineFile != "" }),
	pathField("suppress_file", "suppress", func(c *engine.Config, v string) { c.SuppressFile = v }, func(f *config.FileConfig) bool { return f.SuppressFile != "" }),

	strField("profile", "profile", true,
		func(f *config.FileConfig) string { return f.Profile },
		func(c *engine.Config, v string) { c.Profile = v },
		func(f *config.FileConfig) bool { return f.Profile != "" }),
	strField("fail_on", "fail-on", true,
		func(f *config.FileConfig) string { return f.FailOn },
		func(c *engine.Config, v string) { c.FailOn = v },
		func(f *config.FileConfig) bool { return f.FailOn != "" }),
	strField("min_severity", "min-severity", true,
		func(f *config.FileConfig) string { return f.MinSeverity },
		func(c *engine.Config, v string) { c.MinSeverity = v },
		func(f *config.FileConfig) bool { return f.MinSeverity != "" }),
	strField("diff_base", "diff-base", true,
		func(f *config.FileConfig) string { return f.DiffBase },
		func(c *engine.Config, v string) { c.DiffBase = v },
		func(f *config.FileConfig) bool { return f.DiffBase != "" }),
	strField("include_tests", "include-tests", true,
		func(f *config.FileConfig) string {
			if f.IncludeTestFiles {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.IncludeTestFiles = v == "true" },
		func(f *config.FileConfig) bool { return f.IncludeTestFiles }),
	strField("update_baseline", "update-baseline", true,
		func(f *config.FileConfig) string {
			if f.UpdateBaseline {
				return "true"
			}
			return ""
		},
		func(c *engine.Config, v string) { c.UpdateBaseline = v == "true" },
		func(f *config.FileConfig) bool { return f.UpdateBaseline }),
	numField("min_confidence", "min-confidence", true,
		func(f *config.FileConfig) string {
			if f.MinConfidence > 0 {
				return fmt.Sprint(f.MinConfidence)
			}
			return ""
		},
		func(c *engine.Config, v string) { _, _ = fmt.Sscanf(v, "%g", &c.MinConfidence) },
		func(f *config.FileConfig) bool { return f.MinConfidence > 0 }),
	{label: "tags", flag: "tag", secure: true,
		apply:   func(c *engine.Config, f *config.FileConfig, _ string) { c.Tags = f.Tags },
		present: func(f *config.FileConfig) bool { return len(f.Tags) > 0 }},
	{label: "skip_extensions", flag: "", secure: true,
		apply:   func(c *engine.Config, f *config.FileConfig, _ string) { c.SkipExtensions = f.SkipExtensions },
		present: func(f *config.FileConfig) bool { return len(f.SkipExtensions) > 0 }},
	{label: "boundaries", flag: "", secure: true,
		apply:   func(c *engine.Config, f *config.FileConfig, _ string) { c.Boundaries = f.Boundaries },
		present: func(f *config.FileConfig) bool { return len(f.Boundaries) > 0 }},
}

func pathField(label, flag string, set func(*engine.Config, string), present func(*config.FileConfig) bool) configField {
	return configField{label: label, flag: flag, secure: true, isPath: true,
		apply: func(cfg *engine.Config, fc *config.FileConfig, dir string) {
			var path string
			switch label {
			case "rules_dir":
				path = fc.RulesDir
			case "profiles_dir":
				path = fc.ProfilesDir
			case "policy_dir":
				path = fc.PolicyDir
			case "policy_file":
				path = fc.PolicyFile
			case "baseline_file":
				path = fc.BaselineFile
			case "suppress_file":
				path = fc.SuppressFile
			}
			if path != "" && !filepath.IsAbs(path) {
				path = filepath.Join(dir, path)
			}
			set(cfg, path)
		},
		present: present}
}

// applyConfigValues merges a loaded config file into cfg. changed reports
// explicitly-set CLI flags (they always win over any file). trusted=false
// means the file was auto-discovered from the scanned tree: security fields
// are skipped and their labels returned for the caller's warning.
func applyConfigValues(cfg *engine.Config, fc *config.FileConfig, cfgDir string,
	changed map[string]bool, trusted bool, warn io.Writer,
) []string {
	var ignored []string
	for _, field := range configFields {
		if !field.present(fc) {
			continue
		}
		if field.flag != "" && changed[field.flag] {
			continue // explicit CLI setting wins over any file
		}
		if field.secure && !trusted {
			ignored = append(ignored, field.label)
			continue
		}
		field.apply(cfg, fc, cfgDir)
	}
	if len(ignored) > 0 && warn != nil {
		sort.Strings(ignored)
		// Best-effort diagnostic. A failure to print the warning must not fail
		// the scan, but it is deliberately visible in --verbose output.
		fmt.Fprintf(warn, "minesweep: warning: ignoring security-relevant settings from untrusted config:\n"+ //nolint:errcheck // diagnostic only
			"  %s\n"+
			"  Discovered configs cannot weaken scans. Pass --config <file> to honor them explicitly.\n",
			strings.Join(ignored, ", "))
	}
	return ignored
}

// validateNumericFlags rejects out-of-range numeric settings.
//
// Every one of these had a way to turn into a silently clean scan. A confidence
// threshold above 1 filters out every finding and reports "No secrets or
// sensitive data detected" with exit 0, which is the worst possible failure for
// a gate: it looks like success. A negative --min-confidence disabled the
// default floor as a side effect. `--min-confidence 0` cannot "keep everything"
// despite a comment in engine.go saying so — only --include-low-confidence does
// — so it is rejected as ambiguous rather than silently meaning something
// else.
func validateNumericFlags(cmd *cobra.Command, cfg engine.Config) error {
	// Only flags the user actually named are validated: several of these have a
	// zero default that is a legitimate value (--min-confidence, --workers,
	// --max-files), and rejecting the default would fail every invocation.
	explicit := map[string]bool{}
	cmd.Flags().Visit(func(f *pflag.Flag) { explicit[f.Name] = true })

	if explicit["min-confidence"] {
		if cfg.MinConfidence < 0 || cfg.MinConfidence > 1 {
			return fmt.Errorf("--min-confidence must be between 0.0 and 1.0 (got %g); "+
				"to report findings below the default confidence floor use --include-low-confidence",
				cfg.MinConfidence)
		}
		if cfg.MinConfidence == 0 {
			// Ambiguous rather than merely useless: a comment in engine.go says
			// setting this to 0 keeps everything, and it does not. Saying so is
			// better than quietly applying the default floor.
			return fmt.Errorf("--min-confidence 0 keeps the default confidence floor; " +
				"use --include-low-confidence to disable it")
		}
	}
	nonNegative := []struct {
		flag string
		val  int64
	}{
		{"workers", int64(cfg.Workers)},
		{"max-files", int64(cfg.MaxFiles)},
		{"memory-limit-mb", int64(cfg.MemoryLimitMB)},
		{"max-file-size-mb", cfg.MaxFileSizeMB},
		{"max-concurrent-reads", int64(cfg.MaxConcurrentReads)},
	}
	for _, f := range nonNegative {
		if explicit[f.flag] && f.val < 0 {
			return fmt.Errorf("--%s must not be negative (got %d)", f.flag, f.val)
		}
	}
	if explicit["max-findings"] && cfg.MaxFindings < -1 {
		return fmt.Errorf("--max-findings must be positive, 0 (engine default) or -1 (unlimited) (got %d)",
			cfg.MaxFindings)
	}
	if explicit["runs"] && benchRuns < 1 {
		return fmt.Errorf("--runs must be at least 1 (got %d)", benchRuns)
	}
	if watchMode && watchInterval < 100*time.Millisecond {
		fmt.Fprintf(os.Stderr, "minesweep: warning: --watch-interval raised to 100ms (got %v)\n", watchInterval)
		watchInterval = 100 * time.Millisecond
	}
	return nil
}

func loadConfig(cmd *cobra.Command, scanPath string) error {
	var fileCfg *config.FileConfig
	var cfgPath string
	var err error
	trusted := configPath != ""

	// A config the caller named is parsed strictly. A config found by walking
	// up from the scan target belongs to whatever is being scanned — or to an
	// unrelated project, or to a parent directory — and it must not be able to
	// abort the scan. Unknown keys there are reported and ignored.
	unknown := map[string]bool{}
	reportUnknown := func(key string) { unknown[key] = true }

	if trusted {
		fileCfg, err = config.LoadFile(configPath)
		if err != nil {
			return fmt.Errorf("load config file: %w", err)
		}
		cfgPath = configPath
	} else {
		fileCfg, cfgPath, err = config.FindAndLoadLax(scanPath, reportUnknown)
		if err != nil {
			return fmt.Errorf("load config file: %w", err)
		}
	}
	if len(unknown) > 0 {
		keys := make([]string, 0, len(unknown))
		for k := range unknown {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(os.Stderr, "minesweep: warning: ignoring unrecognised key(s) in %s: %s\n",
			cfgPath, strings.Join(keys, ", "))
	}
	if fileCfg == nil {
		return nil
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Using config file: %s (%s)\n", cfgPath,
			map[bool]string{true: "trusted", false: "discovered"}[trusted])
	}

	changed := map[string]bool{}
	cmd.Flags().Visit(func(f *pflag.Flag) { changed[f.Name] = true })
	applyConfigValues(&cfg, fileCfg, filepath.Dir(cfgPath), changed, trusted, os.Stderr)
	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]
	scanPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s\n\nDouble-check the spelling, or run 'minesweep .' to scan the current directory", scanPath)
	}

	// The CLI's own default is DefaultMaxFindings, so an explicit
	// --max-findings 0 can only mean the user asked for no limit. The engine
	// keeps 0 = "apply the default" for library callers who never set the
	// field; translate so the two meanings do not collide.
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = -1
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if cfg.RulesDir != "" && !filepath.IsAbs(cfg.RulesDir) {
		cfg.RulesDir = filepath.Join(wd, cfg.RulesDir)
	}
	if cfg.PolicyFile != "" && !filepath.IsAbs(cfg.PolicyFile) {
		cfg.PolicyFile = filepath.Join(wd, cfg.PolicyFile)
	}
	if cfg.ProfilesDir != "" && !filepath.IsAbs(cfg.ProfilesDir) {
		cfg.ProfilesDir = filepath.Join(wd, cfg.ProfilesDir)
	}
	if cfg.PolicyDir != "" && !filepath.IsAbs(cfg.PolicyDir) {
		cfg.PolicyDir = filepath.Join(wd, cfg.PolicyDir)
	}

	if watchMode {
		if benchMode {
			return fmt.Errorf("--watch cannot be combined with --benchmark")
		}
		if cfg.HistoryMode {
			return fmt.Errorf("--watch cannot be combined with --history")
		}
		return runWatch(scanPath)
	}

	if benchMode {
		return runBenchmark(scanPath, outputJSON, benchRuns)
	}

	code, err := scanAndReport(scanPath)
	if err != nil {
		return err
	}
	if code != 0 {
		return &exitCodeError{code: code}
	}
	return nil
}

func runWatch(scanPath string) error {
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "minesweep: watching for changes in %s (interval: %v)\n", scanPath, watchInterval)
	}

	watcher := filesystem.NewWatcher([]string{scanPath}, nil, watchInterval)
	watcher.OnChange(func(files []string) {
		fmt.Fprintf(os.Stderr, "\nminesweep: rescanning due to changes...\n")
		// Deliberately ignore the exit code here: findings during watch mode
		// are reported, but must not terminate the watcher.
		if _, err := scanAndReport(scanPath); err != nil {
			fmt.Fprintf(os.Stderr, "minesweep: scan error: %v\n", err)
		}
	})

	if err := watcher.Start(); err != nil {
		return fmt.Errorf("start watcher: %w", err)
	}
	defer watcher.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Fprintf(os.Stderr, "minesweep: watching for changes (press Ctrl+C to stop)\n")
	<-sigCh
	fmt.Fprintf(os.Stderr, "\nminesweep: stopping watcher\n")
	return nil
}

func displayVersion() string {
	if toolVersion == "" {
		return "dev"
	}
	return toolVersion
}

// scanAndReport runs a scan and renders the result. It returns the process
// exit code (0 = clean, 1 = findings at or above --fail-on) but never exits
// itself, so callers such as watch mode can keep running.
func scanAndReport(scanPath string) (int, error) {
	eng, err := engine.New(cfg)
	if err != nil {
		return 0, fmt.Errorf("init engine: %w", err)
	}

	reportData, err := eng.Run(scanPath)
	if err != nil {
		return 0, fmt.Errorf("scan: %w", err)
	}

	// Censor secrets before any output format sees the report.
	if !cfg.DangerouslyShowSecrets {
		reportData = report.CensorReport(reportData)
	}

	// An incomplete scan must never read as a clean one. Exit 2 says "I did
	// not fully look", which is different in kind from exit 1's "I looked and
	// found something": a truncated scan with no findings is the result most
	// likely to be trusted wrongly.
	if reportData != nil && reportData.Incomplete {
		fmt.Fprintf(os.Stderr, "\nminesweep: INCOMPLETE SCAN — results do not cover the whole target.\n")
		for _, reason := range reportData.IncompleteReasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", reason)
		}
		if reportData.FindingsDropped > 0 {
			fmt.Fprintf(os.Stderr, "  - %s\n", fmt.Sprintf("%d findings dropped by the --max-findings cap", reportData.FindingsDropped))
		}
		if reportData.FindingsDiscarded > 0 {
			fmt.Fprintf(os.Stderr, "  - %s\n", fmt.Sprintf("at least %d findings dropped by the per-file finding budget (further matches went uncounted)", reportData.FindingsDiscarded))
		}
	}

	if outputJSON {
		if err := report.WriteJSON(os.Stdout, reportData); err != nil {
			return 0, err
		}
	} else if outputSARIF {
		if err := report.WriteSARIF(os.Stdout, reportData, displayVersion()); err != nil {
			return 0, err
		}
	} else if outputDashboard {
		dashboard := report.GenerateDashboard(reportData)
		if err := report.WriteDashboard(os.Stdout, dashboard, cfg.Verbose); err != nil {
			return 0, err
		}
	} else if showAnnotations {
		minSev := findings.ParseSeverity(cfg.MinSeverity)
		annotations := report.GenerateAnnotations(reportData.Findings, minSev)
		if err := report.WriteGitHubAnnotations(os.Stdout, annotations); err != nil {
			return 0, err
		}
	} else {
		opts := report.TextOptions{
			Verbose:  cfg.Verbose,
			Color:    report.ParseColorMode(colorMode),
			Hints:    nextStepHints(scanPath, reportData),
			Snippets: showSnippets,
		}
		if err := renderTextInteractive(reportData, &opts); err != nil {
			return 0, err
		}
	}

	// Exit 2 is reserved for "the answer is not trustworthy" and outranks the
	// findings check: a caller that gets 2 must not read it as "clean".
	if reportData != nil && reportData.Incomplete {
		return 2, nil
	}
	if reportData != nil {
		minSev := findings.ParseSeverity(cfg.FailOn)
		// --fail-on is documented as "minimum severity that exits non-zero",
		// so it must fire on any finding at or above the threshold regardless
		// of the policy action. The previous implementation also required a
		// non-allow action, and since the default policy maps low and info to
		// allow, `--fail-on low` — the documented default — could never fail on
		// a low-severity finding. A gate that silently does not gate is worse
		// than one that gates too eagerly, because it is trusted.
		for _, f := range reportData.Findings {
			if f.Severity >= minSev {
				return 1, nil
			}
		}
	}
	return 0, nil
}

// nextStepHints suggests beginner-friendly follow-up commands based on the
// scan result and repo state.
func nextStepHints(scanPath string, data *findings.RiskReport) []string {
	var hints []string

	hasFindings := data != nil && len(data.Findings) > 0
	baselineConfigured := cfg.BaselineFile != "" && !cfg.UpdateBaseline

	if hasFindings && !baselineConfigured {
		hints = append(hints, "Already aware of these? Silence them with:\n      minesweep --update-baseline --baseline .minesweep-baseline.json .")
	}

	top := git.TopLevel(scanPath)
	if top != "" && hasFindings && !hasPreCommitHook(top) {
		hints = append(hints, "Block secrets before every commit:\n      minesweep install-hooks")
	}

	if !cfg.Verbose && !cfg.DangerouslyShowSecrets {
		hints = append(hints, "Show hashed values and context:\n      minesweep -v .\n    Reveal raw secrets only when needed:\n      minesweep -v --dangerously-show-secrets .")
	} else if cfg.Verbose && !cfg.DangerouslyShowSecrets {
		hints = append(hints, "Reveal raw secret values:\n      minesweep -v --dangerously-show-secrets .")
	}

	if hasFindings && !showSnippets && len(hints) < 3 {
		hints = append(hints, "Show code snippets with censored values:\n      minesweep --snippets .")
	}

	if len(hints) > 3 {
		hints = hints[:3]
	}
	return hints
}

// hasPreCommitHook reports whether minesweep's pre-commit hook is installed.
//
// It uses the same marker test as install-hooks/uninstall-hooks. The previous
// substring search for "minesweep" reported a hook installed whenever any hook
// merely mentioned the tool — including one whose comment said not to run it —
// so the hint told users to run `minesweep init` for a hook already in place,
// which then refused to overwrite it.
func hasPreCommitHook(repoTop string) bool {
	hookPath, err := hooksDir(repoTop)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(hookPath) //nolint:gosec // hook path inside the named repository
	if err != nil {
		return false
	}
	return isOurHook(string(data))
}

const preCommitHook = `#!/bin/sh
# MineSweep pre-commit hook
# minesweep-pre-commit-hook v1
#
# Scans staged files for secrets before every commit.

# Resolve the scanner binary. We deliberately never execute a minesweep
# binary from inside the repository: a malicious checkout could ship one.
if [ -n "$MINESWEEP_BIN" ] && [ -x "$MINESWEEP_BIN" ]; then
    MINESWEEP="$MINESWEEP_BIN"
elif command -v minesweep >/dev/null 2>&1; then
    MINESWEEP="$(command -v minesweep)"
else
    if [ "$MINESWEEP_HOOK_ALLOW_MISSING" = "1" ]; then
        echo "minesweep: not found on PATH; skipping pre-commit scan (MINESWEEP_HOOK_ALLOW_MISSING=1)" >&2
        exit 0
    fi
    echo "minesweep: not found on PATH - commit blocked (fail-closed)." >&2
    echo "  install:      brew install hxmbl/tap/minesweep" >&2
    echo "  or point at:  export MINESWEEP_BIN=/path/to/minesweep" >&2
    echo "  soft-skip:    export MINESWEEP_HOOK_ALLOW_MISSING=1" >&2
    exit 1
fi

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)
[ -z "$STAGED_FILES" ] && exit 0

echo "minesweep: scanning staged files..."

# Scan the staged index directly. Materializing staged blobs into a temp
# directory read the working tree for present files, missing staged data on
# renames/extensions, and skipped deletions entirely — a file trickily added
# then removed from disk would never be flagged.
"$MINESWEEP" --fail-on medium --no-pager --color never --staged .
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "minesweep: secrets detected in staged files!"
    echo "To bypass: git commit --no-verify"
    exit 1
fi

exit 0
`

// hookMarker identifies a hook this tool installed. Ownership is checked
// against this exact line rather than a substring test for "minesweep", which
// matched any hook that merely mentioned the tool — including a comment in
// somebody else's script — and uninstall-hooks then deleted it.
const hookMarker = "# minesweep-pre-commit-hook v1"

func runInstallHooks(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	hookPath, err := hooksDir(wd)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0750); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	// Refuse to destroy an existing hook. os.WriteFile replaced whatever was
	// there — husky, lint-staged, the pre-commit framework — with no warning,
	// no backup and no --force, while `init` guarded its own output the same
	// way. Losing a team's commit pipeline silently is not recoverable from
	// inside this tool.
	if existing, readErr := os.ReadFile(hookPath); readErr == nil { //nolint:gosec // hook path from git rev-parse
		if !isOurHook(string(existing)) && !hookForce {
			return fmt.Errorf("a pre-commit hook already exists at %s and was not installed by minesweep\n"+
				"  refusing to overwrite it; re-run with --force to replace it, or merge the hook yourself:\n"+
				"    %s",
				hookPath, strings.TrimSpace(firstLines(string(existing), 3)))
		}
		if !isOurHook(string(existing)) {
			backup := hookPath + ".pre-minesweep"
			if err := os.WriteFile(backup, existing, 0o755); err != nil { //nolint:gosec // preserving an executable hook
				return fmt.Errorf("back up existing hook: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Existing hook backed up to %s\n", backup)
		}
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("read existing hook: %w", readErr)
	}

	if err := os.WriteFile(hookPath, []byte(preCommitHook), 0755); err != nil { //nolint:gosec // pre-commit hook must be executable
		return fmt.Errorf("write pre-commit hook: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Installed pre-commit hook: %s\n", hookPath)
	return nil
}

func runUninstallHooks(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	hookPath, err := hooksDir(wd)
	if err != nil {
		return err
	}
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No pre-commit hook found at %s\n", hookPath)
		return nil
	}

	content, err := os.ReadFile(hookPath) //nolint:gosec // hook path from git rev-parse
	if err != nil {
		return fmt.Errorf("read hook: %w", err)
	}
	if !isOurHook(string(content)) {
		return fmt.Errorf("%s was not installed by minesweep; refusing to remove it", hookPath)
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("remove hook: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Removed pre-commit hook: %s\n", hookPath)
	return nil
}

// legacyHookHeader is the first line of the hook this tool installed before the
// marker existed. It is still recognised, so a repository that installed the
// hook with an older version can still recognise and uninstall it; refusing to
// would leave those users with a hook they could not remove and an
// install-hooks that refused to replace it.
const legacyHookHeader = "# MineSweep pre-commit hook"

// isOurHook reports whether a hook script was installed by this tool.
//
// Both the marker line and the legacy header count. The test is deliberately
// not a bare substring search for "minesweep": that matched any hook which
// merely mentioned the tool, including one whose comment said not to run it, and
// uninstall-hooks then deleted somebody else's hook.
func isOurHook(content string) bool {
	if strings.Contains(content, hookMarker) {
		return true
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == legacyHookHeader {
			return true
		}
	}
	return false
}

// hooksDir locates the pre-commit hook for the repository containing dir.
//
// `git rev-parse --git-path hooks` is the authoritative answer. In a linked
// worktree, a submodule, or any checkout reached through GIT_DIR, `.git` is a
// *file* pointing elsewhere, so joining dir/.git/hooks failed with "not a
// directory" and install-hooks simply could not be used there.
//
// When git cannot answer — a directory that has a .git entry but is not a usable
// repository — the conventional <dir>/.git/hooks layout is used if it exists,
// so a read-only probe such as hasPreCommitHook still works. Writing a hook
// through that fallback is not possible in practice, because install-hooks also
// requires a repository and reports one clearly.
func hooksDir(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
	cmd.Dir = dir
	if out, err := cmd.Output(); err == nil {
		p := strings.TrimSpace(string(out))
		if p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			return filepath.Join(p, "pre-commit"), nil
		}
	}

	fallback := filepath.Join(dir, ".git", "hooks")
	info, statErr := os.Stat(fallback)
	if statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("not a git repository (no .git directory found in %s)", dir)
	}
	return filepath.Join(fallback, "pre-commit"), nil
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
