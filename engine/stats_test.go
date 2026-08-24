package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanStatsPlumbed(t *testing.T) {
	dir := t.TempDir()
	sizes := []int{100, 250, 50}
	var total int64
	for i, n := range sizes {
		content := make([]byte, n)
		for j := range content {
			content[j] = 'x'
		}
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".txt"), content, 0644); err != nil {
			t.Fatal(err)
		}
		total += int64(n)
	}

	eng, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	if rep.FilesScanned != len(sizes) {
		t.Errorf("FilesScanned = %d, want %d", rep.FilesScanned, len(sizes))
	}
	if rep.BytesScanned != total {
		t.Errorf("BytesScanned = %d, want %d", rep.BytesScanned, total)
	}
	if rep.DurationMs < 0 {
		t.Error("DurationMs must not be negative")
	}
}

func TestScanStatsSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.txt")
	if err := os.WriteFile(path, []byte("hello world\n"), 0644); err != nil {
		t.Fatal(err)
	}

	eng, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesScanned != 1 || rep.BytesScanned != 12 {
		t.Errorf("stats = (%d files, %d bytes), want (1, 12)", rep.FilesScanned, rep.BytesScanned)
	}
}

func TestMemoryLimitCancelsWithoutRace(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 40; i++ {
		d := filepath.Join(dir, "d")
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f.txt"), []byte("hello world content\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	eng, err := New(Config{MemoryLimitMB: 1, Workers: 8})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil {
		t.Fatal("nil report under memory pressure")
	}
}
