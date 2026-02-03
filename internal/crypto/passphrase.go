package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	// DefaultPassphraseBytes is the number of random bytes for passphrase generation.
	// 32 bytes = 256 bits of entropy, encoded as ~43 base64 characters.
	DefaultPassphraseBytes = 32
)

// GeneratePassphrase creates a cryptographically secure passphrase.
// The passphrase is URL-safe base64 encoded (no padding) for easy handling.
func GeneratePassphrase(numBytes int) (string, error) {
	if numBytes < 16 {
		return "", fmt.Errorf("passphrase must be at least 16 bytes, got %d", numBytes)
	}

	raw := make([]byte, numBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	// URL-safe base64 without padding for easy copy-paste
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
