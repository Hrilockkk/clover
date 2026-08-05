package config

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"scanner/internal/models"
)

func TestEnvInt_Fallback(t *testing.T) {
	// Ensure no env var is set.
	os.Unsetenv("SCANNER_TEST_X")
	got := envInt("SCANNER_TEST_X", 42)
	if got != 42 {
		t.Fatalf("envInt fallback = %d, want 42", got)
	}
}

func TestEnvInt_Value(t *testing.T) {
	t.Setenv("SCANNER_TEST_X", "7")
	got := envInt("SCANNER_TEST_X", 42)
	if got != 7 {
		t.Fatalf("envInt value = %d, want 7", got)
	}
}

func TestEnvInt_Invalid(t *testing.T) {
	t.Setenv("SCANNER_TEST_X", "abc")
	got := envInt("SCANNER_TEST_X", 42)
	if got != 42 {
		t.Fatalf("envInt invalid = %d, want 42", got)
	}
}

func TestCompileRules(t *testing.T) {
	rules := append([]models.SearchRule{}, DefaultRules...)
	compileRules(rules)
	for _, r := range rules {
		if r.Pattern == "" {
			continue
		}
		if len(r.PatternBytes) == 0 {
			t.Fatalf("PatternBytes empty for pattern %q", r.Pattern)
		}
		if r.PatternLower == "" {
			t.Fatalf("PatternLower empty for pattern %q", r.Pattern)
		}
		if r.UTF16 {
			if len(r.UTF16LE) == 0 {
				t.Fatalf("UTF16LE empty for pattern %q", r.Pattern)
			}
			if len(r.UTF16BE) == 0 {
				t.Fatalf("UTF16BE empty for pattern %q", r.Pattern)
			}
		}
	}
}

func TestLoadJSONValid(t *testing.T) {
	jsonData := []byte(`{
  "rules": [
    {"min": 100, "max": 200, "pattern": "TestPattern"}
  ],
  "targetDirNames": ["TestDir"],
  "targetFileNames": ["test.bin"],
  "amcacheExeNames": ["badsoft.exe"]
}`)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.clover")
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		t.Fatalf("write temp json: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Pattern != "TestPattern" {
		t.Fatalf("unexpected rules: %+v", cfg.Rules)
	}
	if len(cfg.TargetDirNames) != 1 || cfg.TargetDirNames[0] != "TestDir" {
		t.Fatalf("unexpected TargetDirNames: %v", cfg.TargetDirNames)
	}
	if len(cfg.TargetFileNames) != 1 || cfg.TargetFileNames[0] != "test.bin" {
		t.Fatalf("unexpected TargetFileNames: %v", cfg.TargetFileNames)
	}
	if len(cfg.AmcacheExeNames) != 1 || cfg.AmcacheExeNames[0] != "badsoft.exe" {
		t.Fatalf("unexpected AmcacheExeNames: %v", cfg.AmcacheExeNames)
	}
}

func TestLoadJSONEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path should not error: %v", err)
	}
	if len(cfg.Rules) != len(DefaultRules) {
		t.Fatalf("expected defaults, got %d rules", len(cfg.Rules))
	}
}

func TestLoadJSONInvalidPath(t *testing.T) {
	_, err := Load("/nonexistent/config.clover")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestGetSingleton(t *testing.T) {
	// Reset once so Get() can be re-evaluated.
	cfgOnce = sync.Once{}
	cfgValue = nil

	t.Setenv("SCANNER_INDEX_WORKERS", "4")
	cfg := Get()
	if cfg.IndexWorkers != 4 {
		t.Fatalf("IndexWorkers = %d, want 4", cfg.IndexWorkers)
	}
	if len(cfg.Rules) != len(DefaultRules) {
		t.Fatalf("len(Rules) = %d, want %d", len(cfg.Rules), len(DefaultRules))
	}
	if cfg.ReaderWorkers != runtime.NumCPU() {
		// fallback should match default unless overridden
		t.Logf("ReaderWorkers = %d (default=%d)", cfg.ReaderWorkers, runtime.NumCPU())
	}
}
