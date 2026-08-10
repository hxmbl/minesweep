package filesystem

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWatcherRaceConditions tests for race conditions in the watcher
func TestWatcherRaceConditions(t *testing.T) {
	// Create a temporary directory with some files
	tmpDir, err := os.MkdirTemp("", "minesweep-watcher-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	for i := 0; i < 10; i++ {
		path := filepath.Join(tmpDir, filepath.Base("file")+string(rune('0'+i))+".txt")
		if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Create watcher
	watcher := NewWatcher([]string{tmpDir}, nil, 100*time.Millisecond)

	// Start the watcher
	if err := watcher.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Wait a bit for initial scan
	time.Sleep(200 * time.Millisecond)

	// Concurrently modify files and access the watcher
	var wg sync.WaitGroup
	
	// Goroutine 1: Modify files
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			for j := 0; j < 10; j++ {
				path := filepath.Join(tmpDir, "file"+string(rune('0'+j))+".txt")
				if err := os.WriteFile(path, []byte("modified"), 0644); err != nil {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 2: Access fileStates (simulating checkChanges)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			// Access fileStates under lock
			watcher.mu.RLock()
			_ = watcher.fileStates
			watcher.mu.RUnlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 3: Call Stop (but don't actually stop until done)
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		// Just access the stopCh, don't close it
		_ = watcher.stopCh
	}()

	wg.Wait()
	// If we get here without a race condition panic, the test passes
}

// TestWatcherConcurrentStartStop tests concurrent Start/Stop calls
func TestWatcherConcurrentStartStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "minesweep-watcher-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var wg sync.WaitGroup
	
	// Start multiple watchers concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watcher := NewWatcher([]string{tmpDir}, nil, 100*time.Millisecond)
			if err := watcher.Start(); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			watcher.Stop()
		}()
	}

	wg.Wait()
	// If we get here without a race condition panic, the test passes
}
