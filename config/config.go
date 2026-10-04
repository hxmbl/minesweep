package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

type FileConfig struct {
	RulesDir         string   `yaml:"rules_dir" json:"rules_dir"`
	ProfilesDir      string   `yaml:"profiles_dir" json:"profiles_dir"`
	PolicyDir        string   `yaml:"policy_dir" json:"policy_dir"`
	Profile          string   `yaml:"profile" json:"profile"`
	PolicyFile       string   `yaml:"policy_file" json:"policy_file"`
	Verbose          bool     `yaml:"verbose" json:"verbose"`
	Boundaries       []string `yaml:"boundaries" json:"boundaries"`
	SkipExtensions   []string `yaml:"skip_extensions" json:"skip_extensions"`
	FailOn           string   `yaml:"fail_on" json:"fail_on"`
	MinConfidence    float64  `yaml:"min_confidence" json:"min_confidence"`
	MinSeverity      string   `yaml:"min_severity" json:"min_severity"`
	Tags             []string `yaml:"tags" json:"tags"`
	Workers          int      `yaml:"workers" json:"workers"`
	DiffBase         string   `yaml:"diff_base" json:"diff_base"`
	BaselineFile     string   `yaml:"baseline_file" json:"baseline_file"`
	UpdateBaseline   bool     `yaml:"update_baseline" json:"update_baseline"`
	SuppressFile     string   `yaml:"suppress_file" json:"suppress_file"`
	IncludeTestFiles bool     `yaml:"include_test_files" json:"include_test_files"`
	// Resource limits
	MaxFiles      int   `yaml:"max_files" json:"max_files"`
	MemoryLimitMB int   `yaml:"memory_limit_mb" json:"memory_limit_mb"`
	MaxFileSizeMB int64 `yaml:"max_file_size_mb" json:"max_file_size_mb"`
	// Concurrency limits
	MaxConcurrentReads int `yaml:"max_concurrent_reads" json:"max_concurrent_reads"`
	// MaxFindings bounds reported findings (0 = engine default).
	MaxFindings int `yaml:"max_findings" json:"max_findings"`
	// NoIgnore disables .minesweepignore/.msignore. It weakens coverage
	// reporting, so an untrusted auto-discovered config may not set it.
	NoIgnore bool `yaml:"no_ignore" json:"no_ignore"`
	// IncludeLowConfidence disables the default confidence floor.
	IncludeLowConfidence bool `yaml:"include_low_confidence" json:"include_low_confidence"`
	// NoInlineSuppressions makes the scanner ignore `minesweep: ignore`
	// comments in scanned content. It only ever surfaces more findings, so it
	// is safe to honour from an auto-discovered config; the converse (granting
	// a repository the ability to suppress its own findings) is not
	// configurable from a file at all.
	NoInlineSuppressions bool `yaml:"no_inline_suppressions" json:"no_inline_suppressions"`
	// DangerouslyShowSecrets prints raw secret values. It is deliberately not
	// configurable from a file: opting in must be a deliberate act on the
	// command line, never something a checked-in config can do for you.
	DangerouslyShowSecrets bool `yaml:"dangerously_show_secrets" json:"dangerously_show_secrets"`
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

// LoadFile parses a config file strictly: an unknown key is an error.
//
// Strictness is right for a file the user named. It is wrong for one that was
// discovered by walking up from the scan target, which may belong to an
// unrelated project, a parent directory, or the repository under examination —
// and which then hard-failed every scan beneath it. Use LoadFileLax for that.
func LoadFile(path string) (*FileConfig, error) {
	return loadFile(path, true)
}

// LoadFileLax parses a config file, collecting unknown keys instead of failing
// on them. Malformed YAML is still an error: that is unreadable input, not
// merely unfamiliar input.
//
// An unknown key is reported through onUnknown so the caller can say which keys
// were ignored. Silently dropping them would leave a typo looking like a
// setting that had taken effect.
func LoadFileLax(path string, onUnknown func(key string)) (*FileConfig, error) {
	return loadFile(path, false, onUnknown)
}

func loadFile(path string, strict bool, onUnknown ...func(string)) (*FileConfig, error) {
	// Reading a path the caller named is the whole purpose of this function.
	data, err := os.ReadFile(path) //nolint:gosec // caller-specified config path
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Always attempt a strict decode first: it is the only way to learn which
	// keys are unknown. A permissive decode would accept the file silently.
	var strictCfg FileConfig
	strictDec := yaml.NewDecoder(bytes.NewReader(data))
	strictDec.KnownFields(true)
	strictErr := strictDec.Decode(&strictCfg)
	if strictErr == nil {
		return &strictCfg, nil
	}
	if strict {
		return nil, fmt.Errorf("parse config file: %w", strictErr)
	}

	// The strict decode failed. If it failed only because of unknown keys,
	// report them and re-read permissively so the known keys still apply.
	unknownKeys := unknownFieldKeys(strictErr)
	if len(unknownKeys) == 0 {
		return nil, fmt.Errorf("parse config file: %w", strictErr)
	}
	if onUnknown != nil && onUnknown[0] != nil {
		for _, k := range unknownKeys {
			onUnknown[0](k)
		}
	}
	var laxCfg FileConfig
	laxDec := yaml.NewDecoder(bytes.NewReader(data))
	laxDec.KnownFields(false)
	if laxErr := laxDec.Decode(&laxCfg); laxErr != nil {
		return nil, fmt.Errorf("parse config file: %w", strictErr)
	}
	return &laxCfg, nil
}

// unknownFieldRe matches yaml.v3's "field X not found in type Y" lines.
var unknownFieldRe = regexp.MustCompile(`field ([^ ]+) not found in type`)

// unknownFieldKeys returns the de-duplicated unknown keys named by a strict
// decode error, in first-seen order. An empty result means the failure was not
// caused by unknown keys and so cannot be downgraded to a warning.
func unknownFieldKeys(err error) []string {
	if err == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range unknownFieldRe.FindAllStringSubmatch(err.Error(), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func FindAndLoad(startDir string) (*FileConfig, string, error) {
	return FindAndLoadLax(startDir, nil)
}

// FindAndLoadLax is FindAndLoad for an auto-discovered config: unknown keys are
// collected rather than fatal.
func FindAndLoadLax(startDir string, onUnknown func(key string)) (*FileConfig, string, error) {
	path := FindConfig(startDir)
	if path == "" {
		return nil, "", nil
	}

	cfg, err := LoadFileLax(path, onUnknown)
	if err != nil {
		return nil, path, err
	}

	return cfg, path, nil
}
