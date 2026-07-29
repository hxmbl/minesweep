package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"minesweep/config"
	"minesweep/engine"
	"minesweep/filesystem"
	"minesweep/findings"
	"minesweep/report"
)

var (
	cfg         engine.Config
	outputJSON  bool
	outputSARIF bool
	outputDashboard bool
	showAnnotations bool
	sarifVersion = "0.1.0"
	configPath  string
	watchMode   bool
	watchInterval time.Duration
)

func main() {
	root := &cobra.Command{
		Use:   "minesweep [path]",
		Short: "MineSweep - policy engine for secrets and sensitive data",
		Long: `MineSweep scans files for secrets, credentials, and sensitive data,
evaluates them against policies, and produces a risk report.`,
		Args: cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "install-hooks" || cmd.Name() == "uninstall-hooks" {
				return nil
			}
			return loadConfig(args[0])
		},
		RunE: runScan,
	}

	root.Flags().StringVarP(&cfg.RulesDir, "rules", "r", "rules", "Directory containing rule YAML files")
	root.Flags().StringVarP(&cfg.PolicyFile, "policy", "", "", "Policy file to evaluate against")
	root.Flags().StringVarP(&cfg.Profile, "profile", "p", "", "Profile name (developer, enterprise, public-github)")
	root.Flags().StringVarP(&cfg.ProfilesDir, "profiles", "", "profiles", "Directory containing profile YAML files")
	root.Flags().BoolVarP(&outputJSON, "json", "", false, "Output as JSON")
	root.Flags().BoolVarP(&outputSARIF, "sarif", "", false, "Output as SARIF (for CI/CD)")
	root.Flags().BoolVarP(&outputDashboard, "dashboard", "", false, "Show rule health dashboard")
	root.Flags().BoolVarP(&showAnnotations, "annotations", "", false, "Show GitHub Actions annotations")
	root.Flags().StringVarP(&cfg.PolicyDir, "policy-dir", "", "policy", "Directory containing policy YAML files")
	root.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
	root.Flags().StringVarP(&cfg.FailOn, "fail-on", "", "low", "Minimum severity that exits non-zero (info, low, medium, high, critical)")
	root.Flags().Float64VarP(&cfg.MinConfidence, "min-confidence", "", 0, "Minimum confidence threshold to include findings (0.0-1.0)")
	root.Flags().StringVarP(&cfg.MinSeverity, "min-severity", "", "", "Minimum severity to report (info, low, medium, high, critical)")
	root.Flags().StringArrayVarP(&cfg.Tags, "tag", "t", nil, "Filter by tag (can be specified multiple times)")
	root.Flags().BoolVarP(&cfg.DiffMode, "diff", "d", false, "Only scan files changed vs base branch")
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

	if err := root.Execute(); err != nil {
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
	if cfg.DiffBase == "main" && fileCfg.DiffBase != "" {
		cfg.DiffBase = fileCfg.DiffBase
	}
	if len(cfg.Boundaries) == 0 && len(fileCfg.Boundaries) > 0 {
		cfg.Boundaries = fileCfg.Boundaries
	}
	if len(cfg.SkipExtensions) == 0 && len(fileCfg.SkipExtensions) > 0 {
		cfg.SkipExtensions = fileCfg.SkipExtensions
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]
	scanPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", scanPath)
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
		return runWatch(scanPath)
	}

	return scanAndReport(scanPath)
}

func runWatch(scanPath string) error {
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "minesweep: watching for changes in %s (interval: %v)\n", scanPath, watchInterval)
	}

	watcher := filesystem.NewWatcher([]string{scanPath}, nil, watchInterval)
	watcher.OnChange(func(files []string) {
		fmt.Fprintf(os.Stderr, "\nminesweep: rescanning due to changes...\n")
		if err := scanAndReport(scanPath); err != nil {
			fmt.Fprintf(os.Stderr, "minesweep: scan error: %v\n", err)
		}
	})

	if err := watcher.Start(); err != nil {
		return fmt.Errorf("start watcher: %w", err)
	}
	defer watcher.Stop()

	fmt.Fprintf(os.Stderr, "minesweep: watching for changes (press Ctrl+C to stop)\n")
	select {}
}

func scanAndReport(scanPath string) error {
	eng, err := engine.New(cfg)
	if err != nil {
		return fmt.Errorf("init engine: %w", err)
	}

	reportData, err := eng.Run(scanPath)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if outputJSON {
		if err := report.WriteJSON(os.Stdout, reportData); err != nil {
			return err
		}
	} else if outputSARIF {
		if err := report.WriteSARIF(os.Stdout, reportData, sarifVersion); err != nil {
			return err
		}
	} else if outputDashboard {
		dashboard := report.GenerateDashboard(reportData)
		if err := report.WriteDashboard(os.Stdout, dashboard, cfg.Verbose); err != nil {
			return err
		}
	} else if showAnnotations {
		minSev := findings.ParseSeverity(cfg.MinSeverity)
		annotations := report.GenerateAnnotations(reportData.Findings, minSev)
		if err := report.WriteGitHubAnnotations(os.Stdout, annotations); err != nil {
			return err
		}
	} else {
		if err := report.WriteText(os.Stdout, reportData, cfg.Verbose); err != nil {
			return err
		}
	}

	if reportData != nil {
		minSev := findings.ParseSeverity(cfg.FailOn)
		for _, f := range reportData.Findings {
			if f.Severity >= minSev && f.Action != findings.ActionAllow {
				os.Exit(1)
			}
		}
	}
	return nil
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

for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        mkdir -p "$TMPDIR/$(dirname "$file")"
        git show ":$file" > "$TMPDIR/$file" 2>/dev/null
    fi
done

# Run minesweep on staged files
"$MINESWEEP" --staged --fail-on medium .
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
	if err := os.WriteFile(hookPath, []byte(preCommitHook), 0755); err != nil {
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
	if !contains(string(content), "MineSweep") {
		return fmt.Errorf("pre-commit hook does not appear to be a minesweep hook")
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("remove hook: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Removed pre-commit hook: %s\n", hookPath)
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
