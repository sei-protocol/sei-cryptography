package zkproofs

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/require"
)

func TestZeroBalanceProof(t *testing.T) {
	tests := []struct {
		name               string
		encryptAmount      *big.Int
		useDifferentPubKey bool
		expectValid        bool
	}{
		{
			name:               "Valid Proof - Correct Encryption and Commitment",
			encryptAmount:      big.NewInt(0),
			useDifferentPubKey: false,
			expectValid:        true,
		},
		{
			name:               "Invalid Proof - Non-Zero Value",
			encryptAmount:      big.NewInt(10000),
			useDifferentPubKey: false,
			expectValid:        false,
		},
		{
			name:               "Invalid Proof - Different Public Key",
			encryptAmount:      big.NewInt(0),
			useDifferentPubKey: true,
			expectValid:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup keypair
			privateKey := testutils.GenerateKey()
			altPrivateKey := testutils.GenerateKey()

			eg := elgamal.NewTwistedElgamal()
			keypair, _ := eg.KeyGen(*privateKey)
			alternativeKeypair, _ := eg.KeyGen(*altPrivateKey)

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
			valid := VerifyZeroBalance(proof, &keypair.PublicKey, ciphertext)
			if valid != tt.expectValid {
				t.Errorf("Expected proof validity to be %v, got %v", tt.expectValid, valid)
			}
		})
	}
}

func TestZeroBalanceProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, _ := eg.KeyGen(*privateKey)

	ciphertext, _, _ := eg.Encrypt(keypair.PublicKey, big.NewInt(0))
	original, err := NewZeroBalanceProof(keypair, ciphertext)
	require.NoError(t, err, "Proof generation should not produce an error")

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

func TestZeroBalanceProof_InvalidRandomness(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, err := eg.KeyGen(*privateKey)
	require.NoError(t, err, "Failed to generate key pair")

	ciphertext, _, err := eg.Encrypt(keypair.PublicKey, big.NewInt(0))
	require.NoError(t, err, "Failed to encrypt amount")

	curve := curves.ED25519()
	Yp := curve.Point.Neg()
	Yd := curve.Point.Double()
	Z := curve.Scalar.Zero()

	invalidProof := &ZeroBalanceProof{
		Yp: Yp,
		Yd: Yd,
		Z:  Z,
	}

	// Verify the proof
	valid := VerifyZeroBalance(invalidProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Proof with invalid randomness fields should fail verification")
}

func TestZeroBalanceProof_ExtremelyLargeScalars(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, err := eg.KeyGen(*privateKey)
	require.NoError(t, err, "Failed to generate key pair")

	ciphertext, _, err := eg.Encrypt(keypair.PublicKey, big.NewInt(0))
	require.NoError(t, err, "Failed to encrypt amount")

	// Manually set Z to an extremely large scalar
	largeScalarBytes := make([]byte, 64) // Adjust size based on curve's scalar size
	_, err = rand.Read(largeScalarBytes)
	require.NoError(t, err, "Failed to generate random bytes for large scalar")

	largeScalar, err := curves.ED25519().Scalar.SetBytesWide(largeScalarBytes)
	require.NoError(t, err, "Failed to set large scalar")

	proof, err := NewZeroBalanceProof(keypair, ciphertext)
	require.NoError(t, err, "Failed to generate proof")

	// Assign the large scalar to Z
	proof.Z = largeScalar

	// Verify the proof
	valid := VerifyZeroBalance(proof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Proof with extremely large scalar Z should fail verification")
}

func TestZeroBalanceProof_TamperedProof(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, err := eg.KeyGen(*privateKey)
	require.NoError(t, err, "Failed to generate key pair")

	ciphertext, _, err := eg.Encrypt(keypair.PublicKey, big.NewInt(0))
	require.NoError(t, err, "Failed to encrypt amount")

	// Generate ZeroBalanceProof
	proof, err := NewZeroBalanceProof(keypair, ciphertext)
	require.NoError(t, err, "Failed to generate proof")

	// Marshal the proof to JSON
	data, err := json.Marshal(proof)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Tamper with the JSON data (e.g., modify the 'z' field)
	var tamperedData map[string]string
	err = json.Unmarshal(data, &tamperedData)
	require.NoError(t, err, "Unmarshaling into map should not produce an error")

	// Modify the 'z' field to an invalid value
	tamperedData["Z"] = "tampered_value"

	// Marshal the tampered data back to JSON
	tamperedJSON, err := json.Marshal(tamperedData)
	require.NoError(t, err, "Marshaling tampered data should not produce an error")

	// Unmarshal the tampered JSON back to a ZeroBalanceProof
	var tamperedProof ZeroBalanceProof
	err = json.Unmarshal(tamperedJSON, &tamperedProof)
	require.Error(t, err, "Unmarshaling tampered JSON should produce an error")
}

// Invalid input: test cases
func TestZeroBalanceProof_InvalidInput(t *testing.T) {
	_, err := NewZeroBalanceProof(nil, nil)
	require.Error(t, err, "Should return an error when keypair is nil")
	require.Contains(t, err.Error(), "keypair is invalid")

	_, err = NewZeroBalanceProof(&elgamal.KeyPair{}, nil)
	require.Error(t, err, "Should return an error when ciphertext is nil")
	require.Contains(t, err.Error(), "keypair is invalid")

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, _ := eg.KeyGen(*privateKey)
	_, err = NewZeroBalanceProof(&elgamal.KeyPair{PublicKey: keypair.PublicKey}, nil)
	require.Error(t, err, "Should return an error when ciphertext is nil")
	require.Contains(t, err.Error(), "keypair is invalid")

	// Test with nil ciphertext
	_, err = NewZeroBalanceProof(keypair, nil)
	require.Error(t, err, "Should return an error when ciphertext is nil")
	require.Contains(t, err.Error(), "ciphertext is invalid")

	// Test with nil D in ciphertext
	invalidCiphertext1 := &elgamal.Ciphertext{C: keypair.PublicKey, D: nil}
	_, err = NewZeroBalanceProof(keypair, invalidCiphertext1)
	require.Error(t, err, "Should return an error when ciphertext.D is nil")
	require.Contains(t, err.Error(), "ciphertext is invalid")

	// Test with nil C in ciphertext
	invalidCiphertext2 := &elgamal.Ciphertext{C: nil, D: keypair.PublicKey}
	_, err = NewZeroBalanceProof(keypair, invalidCiphertext2)
	require.Error(t, err, "Should return an error when ciphertext.C is nil")
	require.Contains(t, err.Error(), "ciphertext is invalid")
}

func TestVerifyZeroProof_InvalidInput(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, err := eg.KeyGen(*privateKey)
	require.NoError(t, err, "Failed to generate key pair")

	ciphertext, _, err := eg.Encrypt(keypair.PublicKey, big.NewInt(0))
	require.NoError(t, err, "Failed to encrypt amount")

	proof, err := NewZeroBalanceProof(keypair, ciphertext)
	require.NoError(t, err, "Failed to generate proof")

	// Test with nil proof
	valid := VerifyZeroBalance(nil, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail when proof is nil")

	nilFieldsProof := &ZeroBalanceProof{}
	valid = VerifyZeroBalance(nilFieldsProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail when proof has nil fields")

	// Test with nil public key
	valid = VerifyZeroBalance(proof, nil, ciphertext)
	require.False(t, valid, "Verification should fail when public key is nil")

	// Test with nil ciphertext
	valid = VerifyZeroBalance(proof, &keypair.PublicKey, nil)
	require.False(t, valid, "Verification should fail when ciphertext is nil")

	// Test with nil D in ciphertext
	invalidCiphertext1 := &elgamal.Ciphertext{C: keypair.PublicKey, D: nil}
	valid = VerifyZeroBalance(proof, &keypair.PublicKey, invalidCiphertext1)
	require.False(t, valid, "Verification should fail when ciphertext.D is nil")

	// Test with nil C in ciphertext
	invalidCiphertext2 := &elgamal.Ciphertext{C: nil, D: keypair.PublicKey}
	valid = VerifyZeroBalance(proof, &keypair.PublicKey, invalidCiphertext2)
	require.False(t, valid, "Verification should fail when ciphertext.C is nil")

	// Test with invalid proof values
	curve := curves.ED25519()
	invalidProof := &ZeroBalanceProof{
		Yp: curve.Point.Neg(),
		Yd: curve.Point.Double(),
		Z:  curve.Scalar.Zero(),
	}
	valid = VerifyZeroBalance(invalidProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail with invalid proof values")

	invalidParamsProof := *proof
	invalidParamsProof.Yp = curves.ED25519().NewIdentityPoint()
	valid = VerifyZeroBalance(&invalidParamsProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail with invalid proof params")

	invalidParamsProof = *proof
	invalidParamsProof.Z = curves.ED25519().Scalar.Zero()
	valid = VerifyZeroBalance(&invalidParamsProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail with invalid proof params")

	invalidParamsProof = *proof
	invalidParamsProof.Yd = nil
	valid = VerifyZeroBalance(&invalidParamsProof, &keypair.PublicKey, ciphertext)
	require.False(t, valid, "Verification should fail with invalid proof params")
}

func TestZeroBalanceProof_IdentityD(t *testing.T) {
	// Setup keypair
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keypair, _ := eg.KeyGen(*privateKey)

	ciphertext, _, err := eg.Encrypt(keypair.PublicKey, big.NewInt(100))
	require.NoError(t, err, "Failed to encrypt amount")

	ciphertextZero, _ := elgamal.SubtractCiphertext(ciphertext, ciphertext)

	// Generate ZeroBalanceProof
	proof, err := NewZeroBalanceProof(keypair, ciphertextZero)
	require.NoError(t, err, "Failed to generate proof")

	// Verify the proof
	valid := VerifyZeroBalance(proof, &keypair.PublicKey, ciphertextZero)
	require.True(t, valid, "Proof should be valid")
}
