package git

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// HistoryObject is a unique object in the repository graph: a blob SHA plus
// one path it is known by. Objects are deduplicated by SHA, so a secret
// living in hundreds of commits costs exactly one scan.
type HistoryObject struct {
	SHA  string
	Path string
	Size int64
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ValidSHA reports whether s looks like an object name we may safely pass as
// a git argument. Everything user- or repo-derived that reaches exec must
// pass through here first.
func ValidSHA(s string) bool {
	return shaPattern.MatchString(s)
}

func gitCmd(root string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	return cmd
}

// ListHistoryObjects returns every unique blob in the repository reachable
// from all refs, with a representative path. Only fixed git subcommands are
// executed; repository data arrives via stdout parsing, never as arguments.
func ListHistoryObjects(root string) ([]HistoryObject, error) {
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}

	revList := gitCmd(top, "rev-list", "--all", "--objects")
	stdout, err := revList.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := revList.Start(); err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}
	defer func() {
		if stdout != nil {
			io.Copy(io.Discard, stdout) //nolint:errcheck // drain so git can exit cleanly
			stdout.Close()
		}
		revList.Wait() //nolint:errcheck // best-effort reaping on early return paths
	}()

	checker, err := newBatchChecker(top)
	if err != nil {
		return nil, err
	}
	defer checker.Close()

	var objects []HistoryObject
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sha, path, _ := strings.Cut(line, " ")
		if !ValidSHA(sha) {
			continue
		}
		objType, size, err := checker.Check(sha)
		if err != nil || objType != "blob" {
			continue // commits and trees have no content to scan
		}
		objects = append(objects, HistoryObject{SHA: sha, Path: path, Size: size})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read rev-list output: %w", err)
	}
	stdout = nil

	if err := revList.Wait(); err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}
	return objects, nil
}

// batchChecker wraps `git cat-file --batch-check`, answering type/size
// questions without transferring object contents.
type batchChecker struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
}

func newBatchChecker(root string) (*batchChecker, error) {
	cmd := gitCmd(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cat-file --batch-check: %w", err)
	}
	return &batchChecker{cmd: cmd, stdin: stdin, out: bufio.NewReaderSize(stdout, 64*1024)}, nil
}

func (b *batchChecker) Check(sha string) (string, int64, error) {
	if _, err := io.WriteString(b.stdin, sha+"\n"); err != nil {
		return "", 0, err
	}
	line, err := b.out.ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", 0, fmt.Errorf("unexpected cat-file response: %q", line)
	}
	if fields[1] == "missing" {
		return "missing", 0, nil
	}
	var size int64
	if len(fields) >= 3 {
		size, _ = strconv.ParseInt(fields[2], 10, 64)
	}
	return fields[1], size, nil
}

func (b *batchChecker) Close() {
	b.stdin.Close()
	b.cmd.Wait() //nolint:errcheck // child cleanup; errors are not actionable
}

// BlobFetcher serves blob contents over a single long-lived
// `git cat-file --batch` process. Requests are serialized internally: the
// request/response protocol cannot interleave.
type BlobFetcher struct {
	root string
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	buf  []byte
	mu   sync.Mutex
}

func NewBlobFetcher(root string) (*BlobFetcher, error) {
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}
	cmd := gitCmd(top, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cat-file --batch: %w", err)
	}
	return &BlobFetcher{root: top, cmd: cmd, in: in, out: bufio.NewReaderSize(out, 256*1024)}, nil
}

// Fetch returns the content of one blob. The returned slice is owned by the
// fetcher and valid only until the next call, from any goroutine.
func (f *BlobFetcher) Fetch(sha string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ValidSHA(sha) {
		return nil, fmt.Errorf("invalid object name: %q", sha)
	}
	if _, err := io.WriteString(f.in, sha+"\n"); err != nil {
		return nil, err
	}
	header, err := f.out.ReadString('\n')
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(strings.TrimSpace(header))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected cat-file header: %q", header)
	}
	if fields[1] == "missing" {
		return nil, fmt.Errorf("object missing: %s", sha)
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("bad object size: %q", header)
	}
	if cap(f.buf) < int(size) {
		f.buf = make([]byte, size)
	}
	buf := f.buf[:size]
	if _, err := io.ReadFull(f.out, buf); err != nil {
		return nil, fmt.Errorf("read blob %s: %w", sha[:min(len(sha), 12)], err)
	}
	// Trailing newline after every object body.
	if _, err := f.out.Discard(1); err != nil {
		return nil, err
	}
	// Hand out a copy: the internal buffer is reused by later fetches, and
	// callers cache results across goroutines.
	out := make([]byte, size)
	copy(out, buf)
	return out, nil
}

func (f *BlobFetcher) Close() {
	f.in.Close()
	f.cmd.Wait() //nolint:errcheck // child cleanup; errors are not actionable
}

// commitAttribution carries who introduced an object into history.
type CommitInfo struct {
	SHA     string
	Author  string
	Date    string
	Summary string
}

// FindOriginCommit identifies the oldest commit in which the given blob
// appears, using git's own object-following machinery. The SHA is validated
// before it ever becomes an argument.
func FindOriginCommit(root, blobSHA string) (*CommitInfo, error) {
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}
	if !ValidSHA(blobSHA) {
		return nil, fmt.Errorf("invalid object name: %q", blobSHA)
	}

	// NUL-separated fields: author names and summaries may contain anything.
	args := []string{
		"log", "--all",
		"--find-object=" + blobSHA,
		"--format=%H%x00%an%x00%aI%x00%s",
	}
	cmd := gitCmd(top, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log --find-object: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, nil // unreachable from any ref, e.g. orphaned blob
	}
	last := lines[len(lines)-1] // oldest commit that touched the object
	fields := strings.SplitN(last, "\x00", 4)
	info := &CommitInfo{SHA: fields[0]}
	if len(fields) > 1 {
		info.Author = fields[1]
	}
	if len(fields) > 2 {
		info.Date = fields[2]
	}
	if len(fields) > 3 {
		info.Summary = fields[3]
	}
	if !ValidSHA(info.SHA) {
		return nil, fmt.Errorf("git returned malformed commit id")
	}
	return info, nil
}
