package obfuscate

import (
	"testing"
)

func TestDecryptKnownStrings(t *testing.T) {
	cases := []struct {
		name string
		fn   func() string
		want string
	}{
		{"CONFIG_MARKER", CONFIG_MARKER, "xK9pL2mQ5vX8wR4t"},
		{"CONTENT_TYPE", CONTENT_TYPE, "Content-Type"},
		{"APP_JSON", APP_JSON, "application/json"},
		{"CMD", CMD, "cmd"},
		{"CMD_C", CMD_C, "/c"},
		{"CONFIG_FILE", CONFIG_FILE, "config.clover"},
		{"JSON_SUFFIX", JSON_SUFFIX, ".json"},
		{"CLOVER_TAG", CLOVER_TAG, "[CLOVER]"},
		{"UPLOAD_TAG", UPLOAD_TAG, "[UPLOAD]"},
	}
	for _, c := range cases {
		if got := c.fn(); got != c.want {
			t.Errorf("%s() = %q, want %q", c.name, got, c.want)
		}
	}
}
