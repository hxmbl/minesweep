package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"minesweep/config"
	"minesweep/engine"
	"minesweep/findings"
	"minesweep/report"
)

var (
	cfg         engine.Config
	outputJSON  bool
	outputSARIF bool
	sarifVersion = "0.1.0"
	configPath  string
)

func main() {
	root := &cobra.Command{
		Use:   "minesweep [path]",
		Short: "MineSweep - policy engine for secrets and sensitive data",
		Long: `MineSweep scans files for secrets, credentials, and sensitive data,
evaluates them against policies, and produces a risk report.`,
		Args: cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
