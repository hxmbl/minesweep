package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"minesweep/findings"
	"minesweep/report"
)

// defaultPager: -R renders ANSI colors, -F exits immediately (printing the
// content) when it fits one screen, -X leaves content on screen after quit.
const defaultPager = "less -FRX"

func noPagerRequested() bool {
	if noPager {
		return true
	}
	switch strings.ToLower(os.Getenv("MINESWEEP_NO_PAGER")) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// stdoutIsTTYFn is indirected for testing.
var stdoutIsTTYFn = stdoutIsTTY

func stdoutIsTTY() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// resolvePagerCommand honors MINESWEEP_PAGER, then GIT_PAGER, then PAGER,
// then the built-in less invocation. Empty/whitespace values fall through
// to the next source so `PAGER=` in some dotfile doesn't break paging.
func resolvePagerCommand() string {
	for _, key := range []string{"MINESWEEP_PAGER", "GIT_PAGER", "PAGER"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return defaultPager
}

// shouldPage reports whether the text report should be routed through a
// pager: only for interactive humans, never in watch mode or machine modes,
// and only when the user has not opted out.
func shouldPage(isTTY bool) bool {
	return isTTY && !watchMode && !noPagerRequested()
}

// renderTextInteractive writes the text report either straight to stdout or
// through the user's pager. When a pager is active, colors are forced on:
// less -R consumes ANSI even though our pipe is not a terminal.
//
// Quitting the pager early (q) breaks the pipe; that is not an error and
// must not change the process exit code.
func renderTextInteractive(r *findings.RiskReport, opts *report.TextOptions) error {
	isTTY := stdoutIsTTYFn()

	if !shouldPage(isTTY) {
		return report.WriteText(os.Stdout, r, *opts)
	}

	fields := strings.Fields(resolvePagerCommand())
	if len(fields) == 0 {
		return report.WriteText(os.Stdout, r, *opts)
	}

	cmd := exec.Command(fields[0], fields[1:]...) //nolint:gosec // pager is user-configured by definition
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return report.WriteText(os.Stdout, r, *opts)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		// Pager missing/broken: degrade to plain output rather than fail.
		fmt.Fprintf(os.Stderr, "minesweep: pager %q unavailable (%v); printing directly\n",
			resolvePagerCommand(), err)
		return report.WriteText(os.Stdout, r, *opts)
	}

	paged := *opts
	paged.Color = report.ColorAlways

	writeErr := report.WriteText(stdin, r, paged)
	stdin.Close()
	waitErr := cmd.Wait()

	if writeErr != nil && errors.Is(writeErr, syscall.EPIPE) {
		writeErr = nil
	}
	if waitErr != nil && errors.Is(waitErr, syscall.EPIPE) {
		waitErr = nil
	}
	if writeErr != nil {
		return writeErr
	}
	return waitErr
}
