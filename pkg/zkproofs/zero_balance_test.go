package zkproofs

import (
	"encoding/json"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestZeroBalanceProof(t *testing.T) {
	tests := []struct {
		name               string
		encryptAmount      uint64
		useDifferentPubKey bool
		expectValid        bool
	}{
		{
			name:               "Valid Proof - Correct Encryption and Commitment",
			encryptAmount:      0,
			useDifferentPubKey: false,
			expectValid:        true,
		},
		{
			name:               "Invalid Proof - Non-Zero Value",
			encryptAmount:      10000,
			useDifferentPubKey: false,
			expectValid:        false,
		},
		{
			name:               "Invalid Proof - Different Public Key",
			encryptAmount:      0,
			useDifferentPubKey: true,
			expectValid:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup keypair
			privateKey, err := elgamal.GenerateKey()
			altPrivateKey, err := elgamal.GenerateKey()

			eg := elgamal.NewTwistedElgamal()
			keypair, err := eg.KeyGen(*privateKey, TestDenom)
			alternativeKeypair, err := eg.KeyGen(*altPrivateKey, TestDenom)

			actualPublicKey := keypair.PublicKey
			if tt.useDifferentPubKey {
				actualPublicKey = alternativeKeypair.PublicKey
			}

			ciphertext, _, err := eg.Encrypt(actualPublicKey, tt.encryptAmount)
			if err != nil {
				t.Fatalf("Failed to encrypt amount: %v", err)
			}

			// Generate ZeroBalanceProof
			proof, err := NewZeroBalanceProof(keypair, ciphertext)
			if err != nil {
				t.Fatalf("Failed to generate proof: %v", err)
			}

			// Verify the proof
			valid := VerifyZeroProof(proof, &keypair.PublicKey, ciphertext)
			if valid != tt.expectValid {
				t.Errorf("Expected proof validity to be %v, got %v", tt.expectValid, valid)
			}
		})
	}
}

func TestZeroBalanceProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey, _ := elgamal.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, _ := eg.KeyGen(*privateKey, TestDenom)

	ciphertext, _, _ := eg.Encrypt(keypair.PublicKey, 0)
	original, err := NewZeroBalanceProof(keypair, ciphertext)

	// Marshal the proof to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a ZeroBalanceProof
	var unmarshaled ZeroBalanceProof
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	// Compare the original and unmarshaled proof
	require.True(t, original.Yp.Equal(unmarshaled.Yp), "Yp points should be equal")
	require.True(t, original.Yd.Equal(unmarshaled.Yd), "Yd points should be equal")
	require.Equal(t, original.Z, unmarshaled.Z, "Z scalars should be equal")
}
