package crypto

import (
	"fmt"
	"io"

	"filippo.io/age"
)

// Encrypt encrypts data using age with a passphrase (scrypt mode).
// The passphrase is used to derive an encryption key using scrypt.
func Encrypt(dst io.Writer, src io.Reader, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("creating recipient: %w", err)
	}

	writer, err := age.Encrypt(dst, recipient)
	if err != nil {
		return fmt.Errorf("creating encryptor: %w", err)
	}

	if _, err := io.Copy(writer, src); err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalizing encryption: %w", err)
	}

	return nil
}

// Decrypt decrypts age-encrypted data using a passphrase.
func Decrypt(dst io.Writer, src io.Reader, passphrase string) error {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return fmt.Errorf("creating identity: %w", err)
	}

	reader, err := age.Decrypt(src, identity)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	if _, err := io.Copy(dst, reader); err != nil {
		return fmt.Errorf("reading decrypted data: %w", err)
	}

	return nil
}
