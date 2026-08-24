package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

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
	colorMode       string
	benchMode       bool
	benchRuns       int
	// toolVersion is stamped at build time via
	// -ldflags "-X main.toolVersion=x.y.z".
	// It must NOT have a package-level constant initializer, otherwise the
	// compiler folds the value into call sites and -X silently no-ops.
	toolVersion   string
	configPath    string
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
			return loadConfig(args[0])
		},
		RunE: runScan,
	}

	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprint(cmd.OutOrStdout(), renderGroupedHelp(cmd))
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
	root.Flags().StringVarP(&colorMode, "color", "", "auto", "When to colorize output: auto, always, never")
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

	root.AddCommand(&cobra.Command{
		Use:   "install-hooks",
		Short: "Install git pre-commit hook",
		Long:  "Install a pre-commit hook that runs minesweep on staged files",
		RunE:  runInstallHooks,
	})

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

func loadConfig(scanPath string) error {
	var fileCfg *config.FileConfig
	var cfgPath string
	var err error

	if configPath != "" {
		fileCfg, err = config.LoadFile(configPath)
		if err != nil {
			return fmt.Errorf("load config file: %w", err)
		}
		cfgPath = configPath
	} else {
		fileCfg, cfgPath, err = config.FindAndLoad(scanPath)
		if err != nil {
			return fmt.Errorf("load config file: %w", err)
		}
	}

	if fileCfg == nil {
		return nil
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", cfgPath)
	}

	applyDefaults(fileCfg)
	return nil
}

func applyDefaults(fileCfg *config.FileConfig) {
	if cfg.RulesDir == "rules" && fileCfg.RulesDir != "" {
		cfg.RulesDir = fileCfg.RulesDir
	}
	if cfg.ProfilesDir == "profiles" && fileCfg.ProfilesDir != "" {
		cfg.ProfilesDir = fileCfg.ProfilesDir
	}
	if cfg.PolicyDir == "policy" && fileCfg.PolicyDir != "" {
		cfg.PolicyDir = fileCfg.PolicyDir
	}
	if cfg.PolicyFile == "" && fileCfg.PolicyFile != "" {
		cfg.PolicyFile = fileCfg.PolicyFile
	}
	if cfg.Profile == "" && fileCfg.Profile != "" {
		cfg.Profile = fileCfg.Profile
	}
	if !cfg.Verbose && fileCfg.Verbose {
		cfg.Verbose = fileCfg.Verbose
	}
	if cfg.FailOn == "low" && fileCfg.FailOn != "" {
		cfg.FailOn = fileCfg.FailOn
	}
	if cfg.MinConfidence == 0 && fileCfg.MinConfidence > 0 {
		cfg.MinConfidence = fileCfg.MinConfidence
	}
	if cfg.MinSeverity == "" && fileCfg.MinSeverity != "" {
		cfg.MinSeverity = fileCfg.MinSeverity
	}
	if len(cfg.Tags) == 0 && len(fileCfg.Tags) > 0 {
		cfg.Tags = fileCfg.Tags
	}
	if cfg.Workers == 0 && fileCfg.Workers > 0 {
		cfg.Workers = fileCfg.Workers
	}
	if cfg.MaxFiles == 0 && fileCfg.MaxFiles > 0 {
		cfg.MaxFiles = fileCfg.MaxFiles
	}
	if cfg.MemoryLimitMB == 0 && fileCfg.MemoryLimitMB > 0 {
		cfg.MemoryLimitMB = fileCfg.MemoryLimitMB
	}
	if cfg.MaxFileSizeMB == 0 && fileCfg.MaxFileSizeMB > 0 {
		cfg.MaxFileSizeMB = fileCfg.MaxFileSizeMB
	}
	if cfg.MaxConcurrentReads == 0 && fileCfg.MaxConcurrentReads > 0 {
		cfg.MaxConcurrentReads = fileCfg.MaxConcurrentReads
	}
	if cfg.DiffBase == "main" && fileCfg.DiffBase != "" {
		cfg.DiffBase = fileCfg.DiffBase
	}
	if len(cfg.Boundaries) == 0 && len(fileCfg.Boundaries) > 0 {
		cfg.Boundaries = fileCfg.Boundaries
	}
	if len(cfg.SkipExtensions) == 0 && len(fileCfg.SkipExtensions) > 0 {
		cfg.SkipExtensions = fileCfg.SkipExtensions
	}
	if cfg.BaselineFile == "" && fileCfg.BaselineFile != "" {
		cfg.BaselineFile = fileCfg.BaselineFile
	}
	if !cfg.UpdateBaseline && fileCfg.UpdateBaseline {
		cfg.UpdateBaseline = true
	}
	if cfg.SuppressFile == "" && fileCfg.SuppressFile != "" {
		cfg.SuppressFile = fileCfg.SuppressFile
	}
	if !cfg.IncludeTestFiles && fileCfg.IncludeTestFiles {
		cfg.IncludeTestFiles = true
	}
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
			Verbose: cfg.Verbose,
			Color:   report.ParseColorMode(colorMode),
			Hints:   nextStepHints(scanPath, reportData),
		}
		if err := report.WriteText(os.Stdout, reportData, opts); err != nil {
			return 0, err
		}
	}

	if reportData != nil {
		minSev := findings.ParseSeverity(cfg.FailOn)
		for _, f := range reportData.Findings {
			if f.Severity >= minSev && f.Action != findings.ActionAllow {
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

	if !cfg.Verbose {
		hints = append(hints, "Show matched values and context:\n      minesweep -v .")
	}

	if len(hints) > 3 {
		hints = hints[:3]
	}
	return hints
}

func hasPreCommitHook(repoTop string) bool {
	data, err := os.ReadFile(filepath.Join(repoTop, ".git", "hooks", "pre-commit"))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "minesweep")
}

const preCommitHook = `#!/bin/sh
# MineSweep pre-commit hook
# Scans staged files for secrets before commit

# Find minesweep binary
MINESWEEP=""
for candidate in minesweep "$(git rev-parse --show-toplevel)/minesweep" "$(which minesweep 2>/dev/null)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        MINESWEEP="$candidate"
        break
    fi
done

if [ -z "$MINESWEEP" ]; then
    echo "minesweep: binary not found, skipping pre-commit hook"
    exit 0
fi

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo "minesweep: scanning staged files..."

# Create temp directory with staged files
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

while IFS= read -r file; do
    if [ -f "$file" ]; then
        mkdir -p "$TMPDIR/$(dirname "$file")"
        git show ":$file" > "$TMPDIR/$file" 2>/dev/null
    fi
done <<EOF
$STAGED_FILES
EOF

# Run minesweep on extracted staged files
"$MINESWEEP" --fail-on medium "$TMPDIR"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "minesweep: secrets detected in staged files!"
    echo "To bypass: git commit --no-verify"
    exit 1
fi

exit 0
`

func runInstallHooks(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	gitDir := filepath.Join(wd, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git directory found)")
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
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

	hookPath := filepath.Join(wd, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No pre-commit hook found at %s\n", hookPath)
		return nil
	}

	// Check if it's our hook
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return fmt.Errorf("read hook: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(content)), "minesweep") {
		return fmt.Errorf("pre-commit hook does not appear to be a minesweep hook")
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("remove hook: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Removed pre-commit hook: %s\n", hookPath)
	return nil
}
