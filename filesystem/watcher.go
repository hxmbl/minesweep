package filesystem

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Watcher struct {
	dirs       []string
	ignore     []string
	interval   time.Duration
	onChange   func(files []string)
	stopCh     chan struct{}
	wg         sync.WaitGroup
	debounce   time.Duration
	lastNotify time.Time
	fileStates map[string]time.Time
	mu         sync.RWMutex
}

type WatchOption struct {
	Include []string
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
		debounce:   500 * time.Millisecond,
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
	close(w.stopCh)
	w.wg.Wait()
}

func (w *Watcher) watch() {
	defer w.wg.Done()
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
	w.mu.RLock()
	defer w.mu.RUnlock()

	var changedFiles []string
	maxFiles := 10000 // Prevent excessive memory usage

	for _, dir := range w.dirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			if len(changedFiles) >= maxFiles {
				return filepath.SkipDir
			}

			if w.shouldIgnore(path) {
				return nil
			}

			// Use RLock for reading
			w.mu.RLock()
			lastMod, exists := w.fileStates[path]
			w.mu.RUnlock()

			if !exists || info.ModTime().After(lastMod) {
				// Use Lock for writing
				w.mu.Lock()
				w.fileStates[path] = info.ModTime()
				w.mu.Unlock()
				changedFiles = append(changedFiles, path)
			}
			return nil
		})
	}

	if len(changedFiles) > 0 && time.Since(w.lastNotify) > w.debounce {
		w.lastNotify = time.Now()
		log.Printf("minesweep: detected %d changed files", len(changedFiles))
		if w.onChange != nil {
			w.onChange(changedFiles)
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
