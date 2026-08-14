package logger

import (
	"io"
	"log/slog"
	"os"
	"sync"
)

var (
	once   sync.Once
	logger *slog.Logger
)

// Default returns the package-level structured logger, initialized to
// write text records to stderr at Info level.
func Default() *slog.Logger {
	once.Do(func() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	})
	return logger
}

// SetLogger replaces the default logger. Useful for tests or for switching to
// JSON output.
func SetLogger(l *slog.Logger) {
	once.Do(func() {})
	logger = l
}

// SetDiscard silences the default logger entirely (used in player-facing
// auto-mode so internal diagnostics never reach the console).
func SetDiscard() {
	SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// SetLevel updates the minimum level of the default logger.
func SetLevel(level slog.Level) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func Info(msg string, args ...any)  { Default().Info(msg, args...) }
func Warn(msg string, args ...any)  { Default().Warn(msg, args...) }
func Error(msg string, args ...any) { Default().Error(msg, args...) }
func Debug(msg string, args ...any) { Default().Debug(msg, args...) }
