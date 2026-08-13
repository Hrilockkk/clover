package embedded

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"scanner/internal/models"
	"scanner/internal/obfuscate"
)

// Config holds the per-link configuration appended to clover.exe by the
// server's download endpoint. The on-disk format is encrypted with AES-256-GCM.
//
// The signature fields (rules and target-name lists) are managed on the site
// («Сигнатуры» page) and embedded fresh at download time; a nil slice means
// "field absent — keep the built-in defaults".
type Config struct {
	ScanID          string              `json:"scanId"`
	UploadURL       string              `json:"uploadUrl"`
	PlayerPassword  string              `json:"playerPassword"`
	Rules           []models.SearchRule `json:"rules,omitempty"`
	TargetDirNames  []string            `json:"targetDirNames,omitempty"`
	TargetFileNames []string            `json:"targetFileNames,omitempty"`
	AmcacheExeNames []string            `json:"amcacheExeNames,omitempty"`
	DriverBlacklist []string            `json:"driverBlacklist,omitempty"`
}

// ReadConfig reads the scanner's own executable, locates the encrypted config
// blob after the obfuscated marker, decrypts it and returns the config. Returns
// nil when running in standalone mode (no embedded config).
func ReadConfig() *Config {
	exePath, err := os.Executable()
	if err != nil {
		return nil
	}
	if real, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = real
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return nil
	}

	cfgBytes, ok := extractConfig(data)
	if !ok || len(cfgBytes) == 0 {
		return nil
	}

	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil
	}
	return &cfg
}

func extractConfig(data []byte) ([]byte, bool) {
	marker := []byte(obfuscate.CONFIG_MARKER())
	if len(data) < len(marker)+4 {
		return nil, false
	}

	searchStart := len(data) - len(marker) - 4 - 65536
	if searchStart < 0 {
		searchStart = 0
	}
	idx := bytesLastIndex(data[searchStart:], marker)
	if idx < 0 {
		return nil, false
	}
	idx += searchStart

	offset := idx + len(marker)
	if offset+4 > len(data) {
		return nil, false
	}
	encLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	if offset+int(encLen) > len(data) {
		return nil, false
	}

	return decryptConfig(data[offset : offset+int(encLen)])
}

func bytesLastIndex(data, sep []byte) int {
	for i := len(data) - len(sep); i >= 0; i-- {
		if i+len(sep) <= len(data) && equalBytes(data[i:i+len(sep)], sep) {
			return i
		}
	}
	return -1
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func legacyConfigKey() []byte {
	key, err := base64.StdEncoding.DecodeString(obfuscate.CONFIG_KEY_B64())
	if err != nil || len(key) != 32 {
		// Fallback to a fixed zero key only in pathological cases; this branch
		// should never be reached with a valid build.
		return make([]byte, 32)
	}
	return key
}

func decryptConfig(data []byte) ([]byte, bool) {
	return aesGCMOpen(legacyConfigKey(), data)
}

const aesGCMNonceSize = 12

func aesGCMOpen(key, data []byte) ([]byte, bool) {
	if len(data) < aesGCMNonceSize {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	if len(data) < gcm.NonceSize() {
		return nil, false
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}
	return plain, true
}

func aesGCMSeal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// EncryptConfig encrypts a config JSON blob with the legacy baked-in key.
func EncryptConfig(plain []byte) ([]byte, error) {
	return aesGCMSeal(legacyConfigKey(), plain)
}

// EncryptPayload encrypts an arbitrary payload with the same key used for the
// embedded config.
func EncryptPayload(plain []byte) ([]byte, error) {
	return EncryptConfig(plain)
}

// EncryptPayloadBase64 encrypts an arbitrary payload and returns it as base64.
func EncryptPayloadBase64(plain []byte) (string, error) {
	enc, err := EncryptPayload(plain)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// DecryptPayloadBase64 decrypts a base64 payload produced by EncryptPayloadBase64.
func DecryptPayloadBase64(encB64 string) ([]byte, error) {
	enc, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	plain, ok := decryptConfig(enc)
	if !ok {
		return nil, fmt.Errorf("decrypt failed")
	}
	return plain, nil
}

// HasEmbedded reports whether the running executable has an embedded config.
func HasEmbedded() bool {
	return ReadConfig() != nil
}

// Summary returns a human-readable description of the embedded config.
func (c *Config) Summary() string {
	if c == nil {
		return "no embedded config (standalone mode)"
	}
	return fmt.Sprintf("scanId=%s uploadUrl=%s", c.ScanID, c.UploadURL)
}
