package shamir

import (
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := []byte("my-super-secret-passphrase")

	tests := []struct {
		name string
		n    int // total shares
		k    int // threshold
	}{
		{"2-of-2", 2, 2},
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-5", 5, 5},
		{"3-of-10", 10, 3},
		{"10-of-10", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := Split(secret, tt.n, tt.k)
			if err != nil {
				t.Fatalf("split: %v", err)
			}

			if len(shares) != tt.n {
				t.Errorf("got %d shares, want %d", len(shares), tt.n)
			}

			// Test with exactly threshold shares
			recovered, err := Combine(shares[:tt.k])
			if err != nil {
				t.Fatalf("combine: %v", err)
			}

			if string(recovered) != string(secret) {
				t.Errorf("got %q, want %q", recovered, secret)
			}
		})
	}
}

func TestSplitCombineAllSubsets(t *testing.T) {
	secret := []byte("test-secret")
	n, k := 5, 3

	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Test all C(5,3) = 10 combinations
	combos := [][]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4},
		{0, 2, 3}, {0, 2, 4}, {0, 3, 4},
		{1, 2, 3}, {1, 2, 4}, {1, 3, 4},
		{2, 3, 4},
	}

	for _, combo := range combos {
		subset := make([][]byte, k)
		for i, idx := range combo {
			subset[i] = shares[idx]
		}

		recovered, err := Combine(subset)
		if err != nil {
			t.Errorf("combine %v: %v", combo, err)
			continue
		}

		if string(recovered) != string(secret) {
			t.Errorf("combo %v: got %q, want %q", combo, recovered, secret)
		}
	}
}

func TestSplitValidation(t *testing.T) {
	secret := []byte("secret")

	tests := []struct {
		name    string
		n       int
		k       int
		wantErr bool
	}{
		{"valid 3-of-5", 5, 3, false},
		{"k=1", 3, 1, true},
		{"k>n", 3, 5, true},
		{"n>255", 300, 3, true},
		{"n=0", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Split(secret, tt.n, tt.k)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCombineInsufficientShares(t *testing.T) {
	_, err := Combine([][]byte{[]byte("single")})
	if err == nil {
		t.Error("expected error with single share")
	}
}

func TestShareEncodeDecode(t *testing.T) {
	original := NewShare(1, 5, 3, "Alice", []byte("test-share-data"))

	encoded := original.Encode()

	decoded, err := ParseShare([]byte(encoded))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version: got %d, want %d", decoded.Version, original.Version)
	}
	if decoded.Index != original.Index {
		t.Errorf("index: got %d, want %d", decoded.Index, original.Index)
	}
	if decoded.Total != original.Total {
		t.Errorf("total: got %d, want %d", decoded.Total, original.Total)
	}
	if decoded.Threshold != original.Threshold {
		t.Errorf("threshold: got %d, want %d", decoded.Threshold, original.Threshold)
	}
	if decoded.Holder != original.Holder {
		t.Errorf("holder: got %q, want %q", decoded.Holder, original.Holder)
	}
	if string(decoded.Data) != string(original.Data) {
		t.Errorf("data: got %q, want %q", decoded.Data, original.Data)
	}
	if decoded.Checksum != original.Checksum {
		t.Errorf("checksum: got %q, want %q", decoded.Checksum, original.Checksum)
	}
}

func TestShareVerify(t *testing.T) {
	share := NewShare(1, 5, 3, "Alice", []byte("test-data"))

	// Valid checksum
	if err := share.Verify(); err != nil {
		t.Errorf("valid share failed verify: %v", err)
	}

	// Corrupted checksum
	share.Checksum = "sha256:wrong"
	if err := share.Verify(); err == nil {
		t.Error("corrupted share should fail verify")
	}
}

func TestShareFilename(t *testing.T) {
	tests := []struct {
		holder   string
		expected string
	}{
		{"Alice", "SHARE-alice.txt"},
		{"Bob Smith", "SHARE-bob-smith.txt"},
		{"Carol!", "SHARE-carol.txt"},
		{"", "SHARE-1.txt"},
	}

	for _, tt := range tests {
		share := NewShare(1, 3, 2, tt.holder, []byte("data"))
		got := share.Filename()
		if got != tt.expected {
			t.Errorf("holder %q: got %q, want %q", tt.holder, got, tt.expected)
		}
	}
}

func TestParseShareInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no markers", "just some text"},
		{"no end", "-----BEGIN REMEMORY SHARE-----\ndata"},
		{"missing fields", "-----BEGIN REMEMORY SHARE-----\nVersion: 1\n-----END REMEMORY SHARE-----"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseShare([]byte(tt.input))
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestAllThresholds tests split/combine for all valid (N,K) from 2-of-2 to 10-of-10
func TestAllThresholds(t *testing.T) {
	secret := []byte("test-passphrase-for-threshold-testing")

	for n := 2; n <= 10; n++ {
		for k := 2; k <= n; k++ {
			t.Run("", func(t *testing.T) {
				shares, err := Split(secret, n, k)
				if err != nil {
					t.Fatalf("%d-of-%d split: %v", k, n, err)
				}

				// Test with exactly k shares
				recovered, err := Combine(shares[:k])
				if err != nil {
					t.Fatalf("%d-of-%d combine: %v", k, n, err)
				}

				if string(recovered) != string(secret) {
					t.Errorf("%d-of-%d: recovered doesn't match", k, n)
				}
			})
		}
	}
}
