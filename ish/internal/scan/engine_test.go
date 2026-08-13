//go:build windows
// +build windows

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	mmap "github.com/edsrzf/mmap-go"
	"scanner/internal/config"
	"scanner/internal/models"
)

func TestEngineAppendResults(t *testing.T) {
	cfg := &config.Cfg{}
	eng := New(cfg, "", "")
	eng.AppendResults(
		[]models.FileInfo{{Path: `C:\a.exe`, Matched: "test"}},
		[]models.DirInfo{{Path: `C:\foo`}},
		[]models.NamedFileInfo{{Path: `C:\token.ms`}},
		[]models.DeletedFileInfo{{Path: `C:\del.exe`}},
		[]models.DeletedDirInfo{{Path: `C:\deldir`}},
	)
	res, dirs, named, delFiles, delDirs, _, _, _, _, _, _, _, _, _, _, _, _ := eng.Results()
	if len(res) != 1 || res[0].Path != `C:\a.exe` {
		t.Fatalf("unexpected results: %v", res)
	}
	if len(dirs) != 1 || dirs[0].Path != `C:\foo` {
		t.Fatalf("unexpected dirs: %v", dirs)
	}
	if len(named) != 1 || named[0].Path != `C:\token.ms` {
		t.Fatalf("unexpected named: %v", named)
	}
	if len(delFiles) != 1 || delFiles[0].Path != `C:\del.exe` {
		t.Fatalf("unexpected delFiles: %v", delFiles)
	}
	if len(delDirs) != 1 || delDirs[0].Path != `C:\deldir` {
		t.Fatalf("unexpected delDirs: %v", delDirs)
	}
}

func TestDedupSlice(t *testing.T) {
	// Verify that dedup logic used in main works.
	seen := make(map[string]bool)
	slice := []models.FileInfo{
		{Path: `C:\a.exe`},
		{Path: `C:\b.exe`},
		{Path: `C:\a.exe`},
	}
	unique := slice[:0]
	for _, f := range slice {
		if !seen[f.Path] {
			seen[f.Path] = true
			unique = append(unique, f)
		}
	}
	if len(unique) != 2 {
		t.Fatalf("dedup len = %d, want 2", len(unique))
	}
}

func TestEngineEnqueuesSelf(t *testing.T) {
	cfg := &config.Cfg{
		Rules: []models.SearchRule{{Min: 0, Max: 1 << 30, Pattern: "x"}},
	}
	eng := New(cfg, `C:\self.exe`, "self.exe")
	ch := make(chan models.FileCandidate, 1)
	eng.EnqueueCandidate(`C:\self.exe`, ch)
	select {
	case <-ch:
		t.Fatal("self exe should not be enqueued")
	default:
	}
}

// feedMatcher is a tiny harness that runs Matcher over a single in-memory file.
func feedMatcher(t *testing.T, cfg *config.Cfg, data []byte) []models.FileInfo {
	t.Helper()
	eng := New(cfg, "", "")
	mappedChan := make(chan models.MappedFile, 1)
	mappedChan <- models.MappedFile{
		Candidate: models.FileCandidate{Path: `C:\t\a.exe`, Name: "a.exe", Size: int64(len(data))},
		Data:      mmap.MMap(data),
		Close:     func() {},
	}
	close(mappedChan)
	eng.Matcher(context.Background(), mappedChan)
	res, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ := eng.Results()
	return res
}

// Regression: a hash-only rule whose SHA256 does NOT match must not swallow
// the remaining rules (bytes.Contains(data, nil) used to break the loop early).
func TestMatcherHashOnlyRuleMissContinues(t *testing.T) {
	data := []byte("hello needle world")
	cfg := &config.Cfg{Rules: []models.SearchRule{
		{Min: 0, Max: 1 << 30, SHA256: strings.Repeat("0", 64)},
		{Min: 0, Max: 1 << 30, Pattern: "needle", PatternBytes: []byte("needle"), PatternLower: "needle"},
	}}
	res := feedMatcher(t, cfg, data)
	if len(res) != 1 || res[0].Matched != "needle" {
		t.Fatalf("expected needle match after hash-rule miss, got %+v", res)
	}
}

// The hash-only rule must match when the digest is right.
func TestMatcherHashOnlyRuleHit(t *testing.T) {
	data := []byte("hello needle world")
	sum := sha256.Sum256(data)
	cfg := &config.Cfg{Rules: []models.SearchRule{
		{Min: 0, Max: 1 << 30, SHA256: hex.EncodeToString(sum[:])},
	}}
	res := feedMatcher(t, cfg, data)
	if len(res) != 1 || !strings.HasPrefix(res[0].Matched, "sha256:") {
		t.Fatalf("expected sha256 match, got %+v", res)
	}
}

// A hash-only rule outside the size range must not interfere at all.
func TestMatcherHashRuleOutOfRange(t *testing.T) {
	data := []byte("hello needle world")
	cfg := &config.Cfg{Rules: []models.SearchRule{
		{Min: 1000, Max: 2000, SHA256: strings.Repeat("0", 64)},
		{Min: 0, Max: 1 << 30, Pattern: "needle", PatternBytes: []byte("needle"), PatternLower: "needle"},
	}}
	res := feedMatcher(t, cfg, data)
	if len(res) != 1 || res[0].Matched != "needle" {
		t.Fatalf("expected needle match, got %+v", res)
	}
}
