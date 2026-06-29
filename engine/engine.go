package engine

import (
	"fmt"
	"os"

	"minesweep/detectors"
	"minesweep/filesystem"
	"minesweep/findings"
	"minesweep/policy"
)

type Config struct {
	RulesDir    string
	ProfilesDir string
	Profile     string
	PolicyFile  string
	Verbose     bool
	Boundaries  []string
}

type Engine struct {
	config    Config
	detectors []detectors.Detector
	policies  []policy.PolicyRule
}

func New(cfg Config) (*Engine, error) {
	if cfg.RulesDir == "" {
		cfg.RulesDir = "rules"
	}
	if cfg.PolicyFile == "" && cfg.Profile == "" {
		cfg.Profile = "default"
	}
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = "profiles"
	}

	regexDetector, err := detectors.NewRegexDetector(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("load regex detector: %w", err)
	}

	detList := []detectors.Detector{
		regexDetector,
		detectors.NewFileTypeDetector(),
		detectors.NewSymlinkDetector(),
	}

	var policies []policy.PolicyRule
	if cfg.Profile != "" {
		policies, err = policy.ResolveProfile(cfg.ProfilesDir, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("resolve profile %q: %w", cfg.Profile, err)
		}
	} else if cfg.PolicyFile != "" {
		policies, err = policy.LoadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("load policy file: %w", err)
		}
	} else {
		policies = defaultPolicies()
	}

	return &Engine{
		config:    cfg,
		detectors: detList,
		policies:  policies,
	}, nil
}

func (e *Engine) Run(path string) (*findings.RiskReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}

	if !info.IsDir() {
		return e.runSingleFile(path)
	}
	return e.runDirectory(path)
}

func (e *Engine) runSingleFile(path string) (*findings.RiskReport, error) {
	file, err := filesystem.NewFile(path)
	if err != nil {
		return nil, err
	}
	allFindings := e.detect(file)
	evaluated := e.evaluate(allFindings)
	report := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &report, nil
}

func (e *Engine) runDirectory(root string) (*findings.RiskReport, error) {
	files, err := filesystem.Walk(root, nil, "")
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	var allFindings []findings.Finding
	for _, file := range files {
		fResults := e.detect(file)
		allFindings = append(allFindings, fResults...)
	}

	evaluated := e.evaluate(allFindings)
	report := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &report, nil
}

func (e *Engine) detect(file *filesystem.File) []findings.Finding {
	var all []findings.Finding
	for _, d := range e.detectors {
		fResults := d.Detect(file)
		all = append(all, fResults...)
	}
	return all
}

func (e *Engine) evaluate(fs []findings.Finding) []findings.Finding {
	var evaluated []findings.Finding
	for _, f := range fs {
		action := policy.Evaluate(f, e.policies)
		f.Reason = string(action) + ": " + f.Reason
		evaluated = append(evaluated, f)
	}
	return evaluated
}

func (e *Engine) Detectors() []detectors.Detector {
	return e.detectors
}

func (e *Engine) Policies() []policy.PolicyRule {
	return e.policies
}

func defaultPolicies() []policy.PolicyRule {
	return []policy.PolicyRule{
		{Tags: []string{"private-key"}, Action: findings.ActionBlock, Reason: "Private keys should never be shared"},
		{Tags: []string{"credentials"}, Action: findings.ActionBlock, MinSeverity: "critical"},
		{Tags: []string{"credentials"}, Action: findings.ActionRedact, MinSeverity: "high"},
		{Tags: []string{"credentials"}, Action: findings.ActionWarn, MinSeverity: "medium"},
		{Tags: []string{"jwt"}, Action: findings.ActionBlock, Reason: "JWT tokens can provide unauthorized access"},
		{Tags: []string{"env"}, Action: findings.ActionWarn},
		{Tags: []string{"cloud"}, Action: findings.ActionRedact, MinSeverity: "high"},
		{Tags: []string{"api-key"}, Action: findings.ActionRedact},
	}
}
