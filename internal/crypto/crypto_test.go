package crypto

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestGeneratePassphrase(t *testing.T) {
	tests := []struct {
		name    string
		bytes   int
		wantErr bool
	}{
		{"default", DefaultPassphraseBytes, false},
		{"minimum", 16, false},
		{"large", 64, false},
		{"too small", 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass, err := GeneratePassphrase(tt.bytes)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pass == "" {
				t.Error("empty passphrase")
			}
			// Check it's valid base64
			if strings.ContainsAny(pass, "+/=") {
				t.Error("passphrase should be URL-safe base64")
			}
		})
	}

	// Test uniqueness
	t.Run("unique", func(t *testing.T) {
		p1, _ := GeneratePassphrase(32)
		p2, _ := GeneratePassphrase(32)
		if p1 == p2 {
			t.Error("passphrases should be unique")
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"small", "hello world"},
		{"empty", ""},
		{"large", strings.Repeat("x", 10000)},
		{"unicode", "Hello 世界 🌍"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passphrase := "test-passphrase-12345"

			// Encrypt
			var encrypted bytes.Buffer
			err := Encrypt(&encrypted, strings.NewReader(tt.data), passphrase)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			// Decrypt
			var decrypted bytes.Buffer
			err = Decrypt(&decrypted, &encrypted, passphrase)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if decrypted.String() != tt.data {
				t.Errorf("got %q, want %q", decrypted.String(), tt.data)
			}
		})
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	data := "secret data"
	passphrase := "correct-passphrase"
	wrongPass := "wrong-passphrase"

	var encrypted bytes.Buffer
	if err := Encrypt(&encrypted, strings.NewReader(data), passphrase); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	err := Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), wrongPass)
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestHashString(t *testing.T) {
	h := HashString("hello")
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("hash should have sha256: prefix, got %s", h)
	}
	if len(h) != 7+64 { // "sha256:" + 64 hex chars
		t.Errorf("unexpected hash length: %d", len(h))
	}

	// Same input should produce same hash
	h2 := HashString("hello")
	if h != h2 {
		t.Error("same input should produce same hash")
	}

	// Different input should produce different hash
	h3 := HashString("world")
	if h == h3 {
		t.Error("different input should produce different hash")
	}
}

func TestHashBytes(t *testing.T) {
	h := HashBytes([]byte{1, 2, 3})
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("hash should have sha256: prefix, got %s", h)
	}
}

func TestHashFile(t *testing.T) {
	// Create a temp file
	dir := t.TempDir()
	path := dir + "/test.txt"
	content := []byte("hello world")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	h, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("hash should have sha256: prefix, got %s", h)
	}

	// Should match HashBytes of the same content
	expected := HashBytes(content)
	if h != expected {
		t.Errorf("HashFile != HashBytes: got %s, want %s", h, expected)
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerifyHash(t *testing.T) {
	hash := HashString("test")

	if !VerifyHash(hash, hash) {
		t.Error("identical hashes should verify")
	}

	if VerifyHash(hash, "sha256:wrong") {
		t.Error("different hashes should not verify")
	}
}

func TestEncryptDecryptInvalidInput(t *testing.T) {
	// Test decrypting non-age data
	var decrypted bytes.Buffer
	err := Decrypt(&decrypted, strings.NewReader("not age encrypted data"), "pass")
	if err == nil {
		t.Error("expected error decrypting invalid data")
	}
}
