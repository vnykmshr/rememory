package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/eljojo/rememory/internal/crypto"
	"github.com/eljojo/rememory/internal/manifest"
	"github.com/eljojo/rememory/internal/project"
	"github.com/eljojo/rememory/internal/shamir"
)

// TestFullWorkflow tests the complete init -> seal -> recover pipeline
func TestFullWorkflow(t *testing.T) {
	// Setup: create a temp directory for the project
	baseDir := t.TempDir()
	projectDir := filepath.Join(baseDir, "test-project")

	// Step 1: Create project (simulating 'rememory init')
	friends := []project.Friend{
		{Name: "Alice", Email: "alice@example.com"},
		{Name: "Bob", Email: "bob@example.com"},
		{Name: "Carol", Email: "carol@example.com"},
		{Name: "David", Email: "david@example.com"},
		{Name: "Eve", Email: "eve@example.com"},
	}
	threshold := 3

	p, err := project.New(projectDir, "test-project", threshold, friends)
	if err != nil {
		t.Fatalf("creating project: %v", err)
	}

	// Add secret content to manifest
	secretContent := "This is my super secret password: hunter2"
	secretFile := filepath.Join(p.ManifestPath(), "secrets.txt")
	if err := os.WriteFile(secretFile, []byte(secretContent), 0644); err != nil {
		t.Fatalf("writing secret: %v", err)
	}

	// Step 2: Seal (simulating 'rememory seal')
	// Archive manifest
	var archiveBuf bytes.Buffer
	if err := manifest.Archive(&archiveBuf, p.ManifestPath()); err != nil {
		t.Fatalf("archiving: %v", err)
	}

	// Generate passphrase
	passphrase, err := crypto.GeneratePassphrase(crypto.DefaultPassphraseBytes)
	if err != nil {
		t.Fatalf("generating passphrase: %v", err)
	}

	// Encrypt
	var encryptedBuf bytes.Buffer
	if err := crypto.Encrypt(&encryptedBuf, bytes.NewReader(archiveBuf.Bytes()), passphrase); err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Split passphrase
	shares, err := shamir.Split([]byte(passphrase), len(friends), threshold)
	if err != nil {
		t.Fatalf("splitting: %v", err)
	}

	// Create share objects with metadata
	shareObjects := make([]*shamir.Share, len(shares))
	for i, data := range shares {
		shareObjects[i] = shamir.NewShare(i+1, len(friends), threshold, friends[i].Name, data)
	}

	// Verify immediate reconstruction
	testShares := make([][]byte, threshold)
	for i := 0; i < threshold; i++ {
		testShares[i] = shares[i]
	}
	recovered, err := shamir.Combine(testShares)
	if err != nil {
		t.Fatalf("verification combine: %v", err)
	}
	if string(recovered) != passphrase {
		t.Fatal("verification failed: passphrase mismatch")
	}

	// Step 3: Simulate share distribution and recovery
	// Test with different share combinations
	combinations := [][]int{
		{0, 1, 2},       // First three
		{2, 3, 4},       // Last three
		{0, 2, 4},       // Alternating
		{1, 2, 3},       // Middle three
		{0, 1, 2, 3, 4}, // All five (should also work)
	}

	for _, combo := range combinations {
		t.Run("", func(t *testing.T) {
			// Simulate encoding/decoding shares (as if read from files)
			recoveryShares := make([]*shamir.Share, len(combo))
			for i, idx := range combo {
				encoded := shareObjects[idx].Encode()
				parsed, err := shamir.ParseShare([]byte(encoded))
				if err != nil {
					t.Fatalf("parsing share %d: %v", idx, err)
				}
				if err := parsed.Verify(); err != nil {
					t.Fatalf("verifying share %d: %v", idx, err)
				}
				recoveryShares[i] = parsed
			}

			// Combine shares
			shareData := make([][]byte, len(recoveryShares))
			for i, s := range recoveryShares {
				shareData[i] = s.Data
			}
			recoveredPass, err := shamir.Combine(shareData)
			if err != nil {
				t.Fatalf("combining: %v", err)
			}

			if string(recoveredPass) != passphrase {
				t.Fatal("recovered passphrase doesn't match")
			}

			// Decrypt
			var decryptedBuf bytes.Buffer
			if err := crypto.Decrypt(&decryptedBuf, bytes.NewReader(encryptedBuf.Bytes()), string(recoveredPass)); err != nil {
				t.Fatalf("decrypting: %v", err)
			}

			// Extract
			extractDir := t.TempDir()
			extractedPath, err := manifest.Extract(&decryptedBuf, extractDir)
			if err != nil {
				t.Fatalf("extracting: %v", err)
			}

			// Verify content
			recoveredSecret, err := os.ReadFile(filepath.Join(extractedPath, "secrets.txt"))
			if err != nil {
				t.Fatalf("reading recovered secret: %v", err)
			}
			if string(recoveredSecret) != secretContent {
				t.Errorf("content mismatch: got %q, want %q", recoveredSecret, secretContent)
			}
		})
	}
}

// TestInsufficientShares verifies that fewer than threshold shares fail
func TestInsufficientShares(t *testing.T) {
	passphrase := "test-passphrase"
	n, k := 5, 3

	shares, err := shamir.Split([]byte(passphrase), n, k)
	if err != nil {
		t.Fatal(err)
	}

	// Try with k-1 shares - should produce wrong result
	insufficient := shares[:k-1]
	recovered, err := shamir.Combine(insufficient)
	if err != nil {
		// Some implementations error, which is fine
		return
	}

	// If no error, the result should be wrong
	if string(recovered) == passphrase {
		t.Error("recovered correct passphrase with insufficient shares - this shouldn't happen")
	}
}

// TestCorruptedShare verifies that corrupted shares are detected
func TestCorruptedShare(t *testing.T) {
	share := shamir.NewShare(1, 5, 3, "Alice", []byte("test-data"))
	encoded := share.Encode()

	// Parse and verify - should work
	parsed, err := shamir.ParseShare([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatal(err)
	}

	// Corrupt the data
	parsed.Data[0] ^= 0xFF

	// Verify should now fail
	if err := parsed.Verify(); err == nil {
		t.Error("corrupted share should fail verification")
	}
}

// TestWrongPassphrase verifies decryption fails with wrong passphrase
func TestWrongPassphrase(t *testing.T) {
	data := []byte("secret data")
	correctPass := "correct-passphrase"
	wrongPass := "wrong-passphrase"

	var encrypted bytes.Buffer
	if err := crypto.Encrypt(&encrypted, bytes.NewReader(data), correctPass); err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	err := crypto.Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), wrongPass)
	if err == nil {
		t.Error("decryption should fail with wrong passphrase")
	}
}

// TestLargeManifest tests with a larger payload (approaching 10MB limit)
func TestLargeManifest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large manifest test in short mode")
	}

	baseDir := t.TempDir()
	manifestDir := filepath.Join(baseDir, "manifest")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a ~1MB file
	largeData := bytes.Repeat([]byte("x"), 1024*1024)
	if err := os.WriteFile(filepath.Join(manifestDir, "large.bin"), largeData, 0644); err != nil {
		t.Fatal(err)
	}

	// Archive
	var archiveBuf bytes.Buffer
	if err := manifest.Archive(&archiveBuf, manifestDir); err != nil {
		t.Fatal(err)
	}

	// Encrypt
	passphrase := "test-passphrase"
	var encrypted bytes.Buffer
	if err := crypto.Encrypt(&encrypted, &archiveBuf, passphrase); err != nil {
		t.Fatal(err)
	}

	// Decrypt
	var decrypted bytes.Buffer
	if err := crypto.Decrypt(&decrypted, &encrypted, passphrase); err != nil {
		t.Fatal(err)
	}

	// Extract and verify
	extractDir := t.TempDir()
	extractedPath, err := manifest.Extract(&decrypted, extractDir)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := os.ReadFile(filepath.Join(extractedPath, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, largeData) {
		t.Error("large file content mismatch")
	}
}

// TestAllThresholdCombinations tests all valid (N,K) from 2-of-2 to 7-of-7
func TestAllThresholdCombinations(t *testing.T) {
	secret := []byte("test-secret-for-threshold-combinations")

	for n := 2; n <= 7; n++ {
		for k := 2; k <= n; k++ {
			t.Run("", func(t *testing.T) {
				// Split
				shares, err := shamir.Split(secret, n, k)
				if err != nil {
					t.Fatalf("%d-of-%d split: %v", k, n, err)
				}

				// Create share objects and encode/decode them
				shareObjs := make([]*shamir.Share, n)
				for i, data := range shares {
					shareObjs[i] = shamir.NewShare(i+1, n, k, "", data)
					encoded := shareObjs[i].Encode()
					parsed, err := shamir.ParseShare([]byte(encoded))
					if err != nil {
						t.Fatalf("parse share %d: %v", i, err)
					}
					if err := parsed.Verify(); err != nil {
						t.Fatalf("verify share %d: %v", i, err)
					}
					shareObjs[i] = parsed
				}

				// Recover with exactly k shares
				recoverData := make([][]byte, k)
				for i := 0; i < k; i++ {
					recoverData[i] = shareObjs[i].Data
				}
				recovered, err := shamir.Combine(recoverData)
				if err != nil {
					t.Fatalf("%d-of-%d combine: %v", k, n, err)
				}
				if string(recovered) != string(secret) {
					t.Errorf("%d-of-%d: secret mismatch", k, n)
				}
			})
		}
	}
}
