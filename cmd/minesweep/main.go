package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"minesweep/engine"
	"minesweep/report"
)

var (
	cfg engine.Config
	outputJSON bool
)

func main() {
	root := &cobra.Command{
		Use:   "minesweep [path]",
		Short: "MineSweep - policy engine for secrets and sensitive data",
		Long: `MineSweep scans files for secrets, credentials, and sensitive data,
evaluates them against policies, and produces a risk report.`,
		Args: cobra.ExactArgs(1),
		RunE: runScan,
	}

	root.Flags().StringVarP(&cfg.RulesDir, "rules", "r", "rules", "Directory containing rule YAML files")
	root.Flags().StringVarP(&cfg.PolicyFile, "policy", "p", "", "Policy file to evaluate against")
	root.Flags().StringVarP(&cfg.Profile, "profile", "", "", "Profile name (developer, enterprise, public-github)")
	root.Flags().StringVarP(&cfg.ProfilesDir, "profiles", "", "profiles", "Directory containing profile YAML files")
	root.Flags().BoolVarP(&outputJSON, "json", "j", false, "Output as JSON")
	root.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")

	if err := root.Execute(); err != nil {
		os.Exit(1)
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
	} else {
		report.WriteText(os.Stdout, reportData, cfg.Verbose)
	}

	if reportData != nil && len(reportData.Findings) > 0 {
		os.Exit(1)
	}
	return nil
}
