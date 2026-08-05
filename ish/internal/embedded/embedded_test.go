package embedded

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"scanner/internal/obfuscate"
)

func TestExtractConfig(t *testing.T) {
	cfg := Config{
		ScanID:    "extract-test",
		UploadURL: "https://example.com/upload",
	}
	plain, _ := json.Marshal(cfg)
	enc, err := EncryptConfig(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	marker := []byte(obfuscate.CONFIG_MARKER())
	data := append(marker, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(data[len(marker):], uint32(len(enc)))
	data = append(data, enc...)

	extracted, ok := extractConfig(data)
	if !ok {
		t.Fatal("extractConfig failed")
	}

	var cfg2 Config
	if err := json.Unmarshal(extracted, &cfg2); err != nil {
		t.Fatalf("unmarshal extracted: %v", err)
	}
	if cfg2 != cfg {
		t.Fatalf("extracted config mismatch: got %+v, want %+v", cfg2, cfg)
	}
}

func TestEncryptDecryptConfig(t *testing.T) {
	cfg := Config{
		ScanID:         "test-scan-id",
		UploadURL:      "https://example.com/api/scan",
		PlayerPassword: "secret123",
	}
	plain, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	enc, err := EncryptConfig(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("encrypted config is empty")
	}

	dec, ok := decryptConfig(enc)
	if !ok {
		t.Fatal("decrypt failed")
	}

	var cfg2 Config
	if err := json.Unmarshal(dec, &cfg2); err != nil {
		t.Fatalf("unmarshal decrypted: %v", err)
	}
	if cfg2 != cfg {
		t.Fatalf("decrypted config mismatch: got %+v, want %+v", cfg2, cfg)
	}
}
