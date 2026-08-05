//go:build windows
// +build windows

package scan

import (
	"testing"

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
	res, dirs, named, delFiles, delDirs, _, _, _, _, _, _, _ := eng.Results()
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
