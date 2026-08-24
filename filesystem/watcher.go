package filesystem

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// pollSkipDirs are pruned from every polling walk. Without this, watch mode
// on a large repository spends each interval statting node_modules and .git.
var pollSkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"target": true, "dist": true, "build": true,
}

type Watcher struct {
	dirs       []string
	ignore     []string
	interval   time.Duration
	onChange   func(files []string)
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	debounce   time.Duration
	lastNotify time.Time
	pending    map[string]bool
	fileStates map[string]time.Time
	mu         sync.RWMutex
}

type WatchOption struct {
	Exclude []string
}

func NewWatcher(dirs []string, opts *WatchOption, interval time.Duration) *Watcher {
	// Enforce minimum interval to prevent CPU exhaustion
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}

	w := &Watcher{
		interval:   interval,
		stopCh:     make(chan struct{}),
		stopOnce:   sync.Once{},
		debounce:   500 * time.Millisecond,
		pending:    make(map[string]bool),
		fileStates: make(map[string]time.Time),
	}

	// Validate and resolve all directories to prevent path traversal
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			continue
		}
		w.dirs = append(w.dirs, abs)
	}

	if opts != nil {
		w.ignore = opts.Exclude
	}

	return w
}

func (w *Watcher) OnChange(fn func(files []string)) {
	w.onChange = fn
}

func (w *Watcher) Start() error {
	// Initialize file states
	for _, dir := range w.dirs {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				w.mu.Lock()
				w.fileStates[path] = info.ModTime()
				w.mu.Unlock()
			}
			return nil
		}); err != nil {
			return err
		}
	}

	w.wg.Add(1)
	go w.watch()
	return nil
}

func (w *Watcher) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.wg.Wait()
}

func (w *Watcher) watch() {
	defer w.wg.Done()

	// For now, use polling mode
	// In the future, we could add fsnotify support for event-driven watching
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.checkChanges()
		}
	}
}

func (w *Watcher) checkChanges() {
	var changedFiles []string
	maxFiles := 10000 // Prevent excessive memory usage

	for _, dir := range w.dirs {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				// Polling walks run every interval; descending into huge,
				// irrelevant trees makes watch mode expensive on big repos.
				if pollSkipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}

			if len(changedFiles) >= maxFiles {
				return filepath.SkipDir
			}

			if w.shouldIgnore(path) {
				return nil
			}

			w.mu.RLock()
			lastMod, exists := w.fileStates[path]
			w.mu.RUnlock()

			if !exists || info.ModTime().After(lastMod) {
				w.mu.Lock()
				w.fileStates[path] = info.ModTime()
				w.mu.Unlock()
				changedFiles = append(changedFiles, path)
			}
			return nil
		}); err != nil {
			log.Printf("minesweep: error walking directory %s: %v", dir, err)
		}
	}

	now := time.Now()
	for _, f := range changedFiles {
		w.pending[f] = true
	}

	// Trailing-edge debounce: changes that arrive inside the debounce window
	// must still trigger a notification once the window closes. The old
	// leading-edge check silently dropped them (their modtimes were already
	// recorded, so no later tick would re-detect them).
	if now.Sub(w.lastNotify) > w.debounce && len(w.pending) > 0 {
		w.lastNotify = now
		files := make([]string, 0, len(w.pending))
		for f := range w.pending {
			files = append(files, f)
		}
		clear(w.pending)
		sort.Strings(files)
		log.Printf("minesweep: detected %d changed files", len(files))
		if w.onChange != nil {
			w.onChange(files)
		}
	}
}

func (w *Watcher) shouldIgnore(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range w.ignore {
		match, err := filepath.Match(pattern, base)
		if err == nil && match {
			return true
		}
	}
	return false
}
