package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A discovered config is, by construction, supplied by whatever is being
// scanned. So security-relevant keys in one — fail_on, profile, suppress_file,
// the resource limits — are ignored unless the user has said otherwise. That
// rule is right, and it has a blind spot: it cannot tell a repository the user
// owns and wrote both the config and the hook in, from one that arrived with a
// `git clone`.
//
// The cost of that blindness is not theoretical. A developer installs the
// pre-commit hook in their own repo, writes .minesweep.yml with the settings
// they want, and finds the hook ignoring all of them while printing
// "Discovered configs cannot weaken scans". The remedy the tool offers is
// `--config <file>`, which a hook cannot pass — the hook is a fixed script. So
// the only way to get a config honoured in a hook is to stop using the hook, or
// to override it, which is a commit-time bypass. The rule that exists to make
// bypassing unnecessary was itself the reason to bypass.
//
// The obvious repair — a marker comment inside the config, such as
// `# minesweep: trust` — does not work. A malicious repository adds that marker
// to the config it ships, which is exactly the weakening the rule forbids. The
// marker would grant an attacker the one capability the rule exists to deny,
// and it would look like a fix.
//
// So trust is expressed where the scanned repository cannot reach it: a
// user-level allowlist outside the working tree. This is the same shape as
// git's safe.directory, which exists for the same reason and faces the same
// dilemma: git cannot tell a repository you own from one you just cloned, so it
// asks you to say so explicitly, and stores the answer in your own config.

// TrustAllEntry trusts every discovered config. It is the equivalent of
// passing --config on every invocation, and it must be typed deliberately.
const TrustAllEntry = "*"

// TrustFileEnv overrides the trust file location. Tests set it; a user with an
// unusual XDG setup can too.
const TrustFileEnv = "MINESWEEP_TRUST_FILE"

// TrustFilePath returns the location of the user-level trust list.
func TrustFilePath() (string, error) {
	if p := os.Getenv(TrustFileEnv); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, "minesweep", "trust"), nil
}

// TrustStore is the parsed contents of the trust list.
type TrustStore struct {
	// Entries are the trusted directories as written, cleaned of surrounding
	// whitespace. TrustAll reports whether the file grants blanket trust.
	Entries  []string
	TrustAll bool
	// Path is where the store was read from or would be written to.
	Path string
}

// LoadTrust reads the trust list. A missing file is an empty store, not an
// error: not having trusted anything is the normal state.
func LoadTrust() (*TrustStore, error) {
	path, err := TrustFilePath()
	if err != nil {
		return nil, err
	}
	store := &TrustStore{Path: path}

	data, err := os.ReadFile(path) //nolint:gosec // path derived from the user's own config dir
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read trust file %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == TrustAllEntry {
			store.TrustAll = true
			continue
		}
		store.Entries = append(store.Entries, filepath.Clean(line))
	}
	return store, nil
}

// Trusts reports whether dir is trusted, and why. The reason is for the
// diagnostic that tells a user their own repo is recognised, which is the whole
// reason the command exists.
func (s *TrustStore) Trusts(dir string) (bool, string) {
	if s == nil {
		return false, ""
	}
	if s.TrustAll {
		return true, "trust file grants blanket trust"
	}
	clean := filepath.Clean(dir)
	abs, err := filepath.Abs(clean)
	if err == nil {
		clean = abs
	}
	for _, e := range s.Entries {
		if e == clean {
			return true, "listed in " + s.Path
		}
	}
	return false, ""
}

// IsTrusted is Trusts without the reason.
func IsTrusted(dir string) bool {
	ok, _ := mustLoadTrust().Trusts(dir)
	return ok
}

// IsTrustedWithReason is IsTrusted with the explanation, for the verbose
// diagnostic. Naming the reason matters more than it looks: a user whose own
// repo is being ignored needs to see that the tool agrees the repo is theirs,
// otherwise the fix looks like it does nothing.
func IsTrustedWithReason(dir string) (bool, string) {
	return mustLoadTrust().Trusts(dir)
}

func mustLoadTrust() *TrustStore {
	store, err := LoadTrust()
	if err != nil {
		return &TrustStore{}
	}
	return store
}

// AddTrust adds dir to the trust list, creating the file if needed. It is
// idempotent, so `minesweep trust .` can be re-run without complaint.
func AddTrust(dir string) error {
	store, err := LoadTrust()
	if err != nil {
		return err
	}
	clean, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	clean = filepath.Clean(clean)
	for _, e := range store.Entries {
		if e == clean {
			return nil
		}
	}
	store.Entries = append(store.Entries, clean)
	return store.write()
}

// RemoveTrust drops dir from the trust list.
func RemoveTrust(dir string) error {
	store, err := LoadTrust()
	if err != nil {
		return err
	}
	clean, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	clean = filepath.Clean(clean)
	kept := store.Entries[:0]
	found := false
	for _, e := range store.Entries {
		if e == clean {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("%s is not in the trust list (%s)", clean, store.Path)
	}
	store.Entries = kept
	return store.write()
}

// write persists the store. The file is written 0600 inside a 0700 directory:
// it is a security decision, and it names the directories a user has decided to
// trust.
func (s *TrustStore) write() error {
	if dir := filepath.Dir(s.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	sort.Strings(s.Entries)

	var b strings.Builder
	b.WriteString("# minesweep trusted repositories.\n")
	b.WriteString("#\n")
	b.WriteString("# Each line is a directory whose discovered .minesweep.yml may set\n")
	b.WriteString("# security-relevant keys (fail_on, profile, suppress_file, the resource\n")
	b.WriteString("# limits). This file lives outside any repository on purpose: a\n")
	b.WriteString("# checkout cannot add itself to it, which is the whole point.\n")
	b.WriteString("#\n")
	b.WriteString("# Manage with: minesweep trust <path> / minesweep untrust <path>\n")
	if s.TrustAll {
		b.WriteString(TrustAllEntry + "\n")
	}
	for _, e := range s.Entries {
		b.WriteString(e + "\n")
	}
	if err := os.WriteFile(s.Path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", s.Path, err)
	}
	return nil
}
