package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"syscall"
	"time"

	"minesweep/engine"
)

type benchRun struct {
	Duration           time.Duration
	Files              int
	Bytes              int64
	Findings           int
	TotalAllocBytes    int64
	RetainedHeapBytes  int64
	PeakRSSBytes       int64
	PeakRSSAvailable   bool
}

type benchSummary struct {
	Path     string
	Runs     []benchRun
	Files    int
	Bytes    int64
	Findings int

	MinDur  time.Duration
	MedDur  time.Duration
	MeanDur time.Duration
	MaxDur  time.Duration

	MeanTotalAlloc   int64
	MeanRetainedHeap int64
	MaxRetainedHeap  int64
	PeakRSSBytes     int64
	PeakRSSAvailable bool
}

func runBenchmark(scanPath string, jsonOut bool, runs int) error {
	if runs < 1 {
		runs = 1
	}

	if !jsonOut {
		fmt.Fprintf(os.Stderr, "minesweep: warming up (untimed)...\n")
	}

	eng, err := engine.New(cfg)
	if err != nil {
		return fmt.Errorf("init engine: %w", err)
	}

	warm, err := eng.Run(scanPath)
	if err != nil {
		return fmt.Errorf("warmup scan: %w", err)
	}
	files := warm.FilesScanned
	bytes := warm.BytesScanned
	findings := len(warm.Findings)

	results := make([]benchRun, 0, runs)
	for i := 0; i < runs; i++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		rssBefore, _ := peakRSSBytes()

		start := time.Now()
		rep, err := eng.Run(scanPath)
		elapsed := time.Since(start)
		if err != nil {
			return fmt.Errorf("benchmark run %d: %w", i+1, err)
		}

		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		rssAfter, rssOK := peakRSSBytes()

		var totalAlloc int64
		if after.TotalAlloc >= before.TotalAlloc {
			totalAlloc = int64(after.TotalAlloc - before.TotalAlloc) //nolint:gosec
		}
		retained := int64(after.HeapAlloc) //nolint:gosec
		peakRSS := rssAfter
		if rssOK && rssBefore > peakRSS {
			peakRSS = rssBefore
		}

		results = append(results, benchRun{
			Duration:          elapsed,
			Files:             rep.FilesScanned,
			Bytes:             rep.BytesScanned,
			Findings:          len(rep.Findings),
			TotalAllocBytes:   totalAlloc,
			RetainedHeapBytes: retained,
			PeakRSSBytes:      peakRSS,
			PeakRSSAvailable:  rssOK,
		})
	}

	summary := summarizeBench(scanPath, results, files, bytes, findings)

	if jsonOut {
		return writeBenchJSON(summary)
	}
	writeBenchText(summary)
	return nil
}

func summarizeBench(path string, results []benchRun, files int, bytes int64, findings int) benchSummary {
	if len(results) == 0 {
		return benchSummary{
			Path:     path,
			Files:    files,
			Bytes:    bytes,
			Findings: findings,
		}
	}

	durs := make([]time.Duration, 0, len(results))
	var totalAllocSum int64
	var retainedSum int64
	var maxRetained int64
	var peakRSS int64
	peakRSSAvail := false
	for _, r := range results {
		durs = append(durs, r.Duration)
		totalAllocSum += r.TotalAllocBytes
		retainedSum += r.RetainedHeapBytes
		if r.RetainedHeapBytes > maxRetained {
			maxRetained = r.RetainedHeapBytes
		}
		if r.PeakRSSAvailable {
			peakRSSAvail = true
			if r.PeakRSSBytes > peakRSS {
				peakRSS = r.PeakRSSBytes
			}
		}
	}
	sorted := append([]time.Duration(nil), durs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	minDur, maxDur := sorted[0], sorted[len(sorted)-1]
	for _, d := range durs {
		sum += d
	}
	mean := sum / time.Duration(len(durs))

	return benchSummary{
		Path:             path,
		Runs:             results,
		Files:            files,
		Bytes:            bytes,
		Findings:         findings,
		MinDur:           minDur,
		MedDur:           medianDuration(sorted),
		MeanDur:          mean,
		MaxDur:           maxDur,
		MeanTotalAlloc:   totalAllocSum / int64(len(results)),
		MeanRetainedHeap: retainedSum / int64(len(results)),
		MaxRetainedHeap:  maxRetained,
		PeakRSSBytes:     peakRSS,
		PeakRSSAvailable: peakRSSAvail,
	}
}

func medianDuration(sorted []time.Duration) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func writeBenchText(s benchSummary) {
	fmt.Println("MineSweep Benchmark")
	fmt.Println()
	printStat("Path:", s.Path)
	printStat("Runs:", fmt.Sprintf("%d (+1 warmup)", len(s.Runs)))
	fmt.Println()

	printStat("Files:", formatCount(s.Files))
	printStat("Bytes:", formatByteSize(s.Bytes))
	printStat("Findings:", formatCount(s.Findings))
	fmt.Println()

	fmt.Println("Scan times:")
	printStat("  min:", formatDurationShort(s.MinDur))
	printStat("  median:", formatDurationShort(s.MedDur))
	printStat("  mean:", formatDurationShort(s.MeanDur))
	printStat("  max:", formatDurationShort(s.MaxDur))
	fmt.Println()

	if s.MeanDur > 0 {
		secs := s.MeanDur.Seconds()
		fmt.Println("Throughput (mean):")
		printStat("  files/s:", formatCount(int(float64(s.Files)/secs)))
		printStat("  MB/s:", fmt.Sprintf("%.1f", float64(s.Bytes)/(secs*1024*1024)))
		fmt.Println()
	}

	fmt.Println("Memory:")
	printStat("  total alloc/run (mean):", formatByteSize(s.MeanTotalAlloc))
	printStat("  retained heap (mean):", formatByteSize(s.MeanRetainedHeap))
	printStat("  retained heap (max):", formatByteSize(s.MaxRetainedHeap))
	if s.PeakRSSAvailable {
		printStat("  peak RSS (process):", formatByteSize(s.PeakRSSBytes))
	} else {
		printStat("  peak RSS (process):", "unavailable")
	}
	printStat("  note:", "Alloc delta is not peak memory; see total alloc, retained heap, and peak RSS")
}

func writeBenchJSON(s benchSummary) error {
	type statJSON struct {
		Min    float64 `json:"min"`
		Median float64 `json:"median"`
		Mean   float64 `json:"mean"`
		Max    float64 `json:"max"`
	}
	type memoryJSON struct {
		TotalAllocBytesMean  int64  `json:"total_alloc_bytes_mean"`
		RetainedHeapBytesMean int64 `json:"retained_heap_bytes_mean"`
		RetainedHeapBytesMax  int64 `json:"retained_heap_bytes_max"`
		PeakRSSBytes          *int64 `json:"peak_rss_bytes"`
		Note                  string `json:"note"`
	}
	type benchJSON struct {
		Benchmark   bool       `json:"benchmark"`
		Path        string     `json:"path"`
		Runs        int        `json:"runs"`
		Files       int        `json:"files"`
		Bytes       int64      `json:"bytes"`
		Findings    int        `json:"findings"`
		TimesMs     statJSON   `json:"times_ms"`
		FilesPerSec float64    `json:"files_per_sec,omitempty"`
		BytesPerSec float64    `json:"bytes_per_sec,omitempty"`
		Memory      memoryJSON `json:"memory"`
	}

	var peak *int64
	if s.PeakRSSAvailable {
		v := s.PeakRSSBytes
		peak = &v
	}
	out := benchJSON{
		Benchmark: true,
		Path:      s.Path,
		Runs:      len(s.Runs),
		Files:     s.Files,
		Bytes:     s.Bytes,
		Findings:  s.Findings,
		TimesMs: statJSON{
			Min:    msFloat(s.MinDur),
			Median: msFloat(s.MedDur),
			Mean:   msFloat(s.MeanDur),
			Max:    msFloat(s.MaxDur),
		},
		Memory: memoryJSON{
			TotalAllocBytesMean:   s.MeanTotalAlloc,
			RetainedHeapBytesMean: s.MeanRetainedHeap,
			RetainedHeapBytesMax:  s.MaxRetainedHeap,
			PeakRSSBytes:          peak,
			Note:                  "Alloc delta is not peak memory; reports total allocation, retained heap, and process peak RSS when available.",
		},
	}
	if s.MeanDur > 0 {
		out.FilesPerSec = float64(s.Files) / s.MeanDur.Seconds()
		out.BytesPerSec = float64(s.Bytes) / s.MeanDur.Seconds()
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printStat(label, value string) {
	fmt.Printf("%-16s%s\n", label, value)
}

func formatCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, c)
	}
	return string(b)
}

func formatByteSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	val := float64(b) / unit
	for _, u := range []string{"KB", "MB", "GB", "TB"} {
		if val < unit {
			return fmt.Sprintf("%.1f %s", val, u)
		}
		val /= unit
	}
	return fmt.Sprintf("%.1f PB", val)
}

func formatDurationShort(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.0fµs", float64(d.Nanoseconds())/1e3)
	}
}

func msFloat(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}

func peakRSSBytes() (int64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	rss := ru.Maxrss
	if rss <= 0 {
		return 0, false
	}
	// Darwin reports bytes, Linux reports kilobytes.
	switch runtime.GOOS {
	case "darwin":
		return rss, true
	default:
		return rss * 1024, true
	}
}
