package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type FileConfig struct {
	RulesDir       string   `yaml:"rules_dir" json:"rules_dir"`
	ProfilesDir    string   `yaml:"profiles_dir" json:"profiles_dir"`
	PolicyDir      string   `yaml:"policy_dir" json:"policy_dir"`
	Profile        string   `yaml:"profile" json:"profile"`
	PolicyFile     string   `yaml:"policy_file" json:"policy_file"`
	Verbose        bool     `yaml:"verbose" json:"verbose"`
	Boundaries     []string `yaml:"boundaries" json:"boundaries"`
	SkipExtensions []string `yaml:"skip_extensions" json:"skip_extensions"`
	FailOn         string   `yaml:"fail_on" json:"fail_on"`
	MinConfidence  float64  `yaml:"min_confidence" json:"min_confidence"`
	MinSeverity    string   `yaml:"min_severity" json:"min_severity"`
	Tags           []string `yaml:"tags" json:"tags"`
	Workers        int      `yaml:"workers" json:"workers"`
	DiffBase       string   `yaml:"diff_base" json:"diff_base"`
	// Resource limits
	MaxFiles       int   `yaml:"max_files" json:"max_files"`
	MemoryLimitMB   int   `yaml:"memory_limit_mb" json:"memory_limit_mb"`
	MaxFileSizeMB   int64 `yaml:"max_file_size_mb" json:"max_file_size_mb"`
	// Concurrency limits
	MaxConcurrentReads int `yaml:"max_concurrent_reads" json:"max_concurrent_reads"`
}

var configNames = []string{".minesweep.yml", ".minesweep.yaml", "minesweep.yml", "minesweep.yaml"}

func FindConfig(startDir string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return ""
	}

	for {
		for _, name := range configNames {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func LoadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &cfg, nil
}

func FindAndLoad(startDir string) (*FileConfig, string, error) {
	path := FindConfig(startDir)
	if path == "" {
		return nil, "", nil
	}

	cfg, err := LoadFile(path)
	if err != nil {
		return nil, path, err
	}

	return cfg, path, nil
}
