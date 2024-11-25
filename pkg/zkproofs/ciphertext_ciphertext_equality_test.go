package zkproofs

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const TestDenom = "factory/sei15zv4wz8kpa4jz5ahretje97u5xsp9vttvyaffd/testToken"

func TestCiphertextCiphertextEqualityProof(t *testing.T) {
	tests := []struct {
		name                  string
		sourceAmount          *big.Int
		destinationAmount     *big.Int
		useDifferentPublicKey bool
		expectValid           bool
	}{
		{
			name:                  "Valid Proof - Equal Amounts",
			sourceAmount:          big.NewInt(100),
			destinationAmount:     big.NewInt(100),
			useDifferentPublicKey: false,
			expectValid:           true,
		},
		{
			name:                  "Invalid Proof - Mismatched Amounts",
			sourceAmount:          big.NewInt(100),
			destinationAmount:     big.NewInt(101),
			useDifferentPublicKey: false,
			expectValid:           false,
		},
		{
			name:                  "Invalid Proof - Wrong Dest Public Key",
			sourceAmount:          big.NewInt(200),
			destinationAmount:     big.NewInt(200),
			useDifferentPublicKey: true,
			expectValid:           false,
		},
		{
			name:                  "Invalid Proof - Different Public Keys and Mismatched Amounts",
			sourceAmount:          big.NewInt(150),
			destinationAmount:     big.NewInt(151),
			useDifferentPublicKey: true,
			expectValid:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Key generation
			sourcePrivateKey, _ := testutils.GenerateKey()
			destPrivateKey, _ := testutils.GenerateKey()
			eg := elgamal.NewTwistedElgamal()
			sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)
			destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

			var actualDestinationPubkey *curves.Point
			if tt.useDifferentPublicKey {
				altDestPrivateKey, _ := testutils.GenerateKey()
				// Generate an alternative keypair for destination
				altDestinationKeypair, _ := eg.KeyGen(*altDestPrivateKey, TestDenom)
				actualDestinationPubkey = &altDestinationKeypair.PublicKey
			} else {
				actualDestinationPubkey = &destinationKeypair.PublicKey
			}

			// Encrypt the source amount
			sourceCiphertext, _, err := eg.Encrypt(sourceKeypair.PublicKey, tt.sourceAmount)
			assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

			// Encrypt the destination amount
			destinationCiphertext, destinationRandomness, err := eg.Encrypt(destinationKeypair.PublicKey, tt.destinationAmount)
			assert.NoError(t, err, "Encryption should succeed for destinationCiphertext")

			amount, _ := curves.ED25519().Scalar.SetBigInt(tt.sourceAmount)

			// Generate the proof
			proof, err := NewCiphertextCiphertextEqualityProof(
				sourceKeypair,
				actualDestinationPubkey,
				sourceCiphertext,
				&destinationRandomness,
				&amount,
			)
			assert.NoError(t, err, "Proof generation should not fail")

			// VerifyCiphertextCiphertextEquality the proof
			valid := VerifyCiphertextCiphertextEquality(
				proof,
				&sourceKeypair.PublicKey,
				actualDestinationPubkey,
				sourceCiphertext,
				destinationCiphertext,
			)

			if tt.expectValid {
				assert.True(t, valid, "Proof verification should succeed")
			} else {
				assert.False(t, valid, "Proof verification should fail")
			}
		})
	}
}

func TestCiphertextCiphertextEqualityProof_EdgeCases(t *testing.T) {
	t.Run("Zero Amounts", func(t *testing.T) {
		// Key generation
		sourcePrivateKey, _ := testutils.GenerateKey()
		destPrivateKey, _ := testutils.GenerateKey()
		eg := elgamal.NewTwistedElgamal()
		sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)
		destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

		amount := big.NewInt(0)

		// Encrypt the amount using source and destination public keys
		sourceCiphertext, _, err := eg.Encrypt(sourceKeypair.PublicKey, amount)
		assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

		destinationCiphertext, destinationRandomness, err := eg.Encrypt(destinationKeypair.PublicKey, amount)
		assert.NoError(t, err, "Encryption should succeed for destinationCiphertext")

		scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

		// Generate the proof
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			&destinationRandomness,
			&scalarAmount,
		)
		assert.NoError(t, err, "Proof generation should succeed for zero amounts")

		// VerifyCiphertextCiphertextEquality the proof
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			destinationCiphertext,
		)
		assert.True(t, valid, "Proof verification should succeed for zero amounts")
	})

	t.Run("Maximum Amount", func(t *testing.T) {
		// Key generation
		sourcePrivateKey, _ := testutils.GenerateKey()
		destPrivateKey, _ := testutils.GenerateKey()
		eg := elgamal.NewTwistedElgamal()
		sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

		destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

		amount := big.NewInt(1 << 60) // A large amount to test scalability

		// Encrypt the amount using source and destination public keys
		sourceCiphertext, _, err := eg.Encrypt(sourceKeypair.PublicKey, amount)
		assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

		destinationCiphertext, destinationRandomness, err := eg.Encrypt(destinationKeypair.PublicKey, amount)
		assert.NoError(t, err, "Encryption should succeed for destinationCiphertext")

		// Generate the proof
		scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

		// Generate the proof
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			&destinationRandomness,
			&scalarAmount,
		)
		assert.NoError(t, err, "Proof generation should succeed for maximum amounts")

		// VerifyCiphertextCiphertextEquality the proof
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			destinationCiphertext,
		)
		assert.True(t, valid, "Proof verification should succeed for maximum amounts")
	})
}

func TestCiphertextCiphertextEqualityProof_UnmarshalJSON_Valid(t *testing.T) {
	sourcePrivateKey, _ := testutils.GenerateKey()
	destPrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)
	destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

	amount := big.NewInt(100)

	// Encrypt the amount using source and destination public keys
	sourceCiphertext, _, _ := eg.Encrypt(sourceKeypair.PublicKey, amount)
	_, destinationRandomness, _ := eg.Encrypt(destinationKeypair.PublicKey, amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	proof, err := NewCiphertextCiphertextEqualityProof(
		sourceKeypair,
		&destinationKeypair.PublicKey,
		sourceCiphertext,
		&destinationRandomness,
		&scalarAmount,
	)
	require.NoError(t, err, "Proof generation should not fail")

	// Marshal the proof to JSON
	data, err := proof.MarshalJSON()
	require.NoError(t, err, "Marshaling should not fail")

	// Unmarshal the JSON back to a proof
	var unmarshaled CiphertextCiphertextEqualityProof
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not fail")

	// Type assert to CiphertextCiphertextEqualityProof
	//unmarshaledProof, ok := unmarshaled.(*CiphertextCiphertextEqualityProof)
	//require.True(t, ok, "Unmarshaled proof should be of type CiphertextCiphertextEqualityProof")

	// Compare original and unmarshaled proofs
	require.True(t, proof.Y0.Equal(unmarshaled.Y0), "Y0 points should be equal after unmarshaling")
	require.True(t, proof.Y1.Equal(unmarshaled.Y1), "Y1 points should be equal after unmarshaling")
	require.True(t, proof.Y2.Equal(unmarshaled.Y2), "Y2 points should be equal after unmarshaling")
	require.True(t, proof.Y3.Equal(unmarshaled.Y3), "Y3 points should be equal after unmarshaling")
	require.Equal(t, proof.Zs, unmarshaled.Zs, "Zs scalars should be equal after unmarshaling")
	require.Equal(t, proof.Zx, unmarshaled.Zx, "Zx scalars should be equal after unmarshaling")
	require.Equal(t, proof.Zr, unmarshaled.Zr, "Zr scalars should be equal after unmarshaling")
}

// Invalid input tests for NewCiphertextCiphertextEqualityProof
func TestNewCiphertextCiphertextEqualityProof_InvalidInputs(t *testing.T) {
	sourcePrivateKey, _ := testutils.GenerateKey()
	destPrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)
	destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

	amount := big.NewInt(100)

	// Encrypt the amount using source and destination public keys
	sourceCiphertext, _, _ := eg.Encrypt(sourceKeypair.PublicKey, amount)
	_, destinationRandomness, _ := eg.Encrypt(destinationKeypair.PublicKey, amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	t.Run("Invalid Source Keypair", func(t *testing.T) {
		// Source keypair is nil
		proof, err := NewCiphertextCiphertextEqualityProof(
			nil,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			&destinationRandomness,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil source keypair")
		require.Nil(t, proof, "Proof should be nil for nil source keypair")
	})

	t.Run("Invalid Destination Public Key", func(t *testing.T) {
		// Destination public key is nil
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			nil,
			sourceCiphertext,
			&destinationRandomness,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil destination public key")
		require.Nil(t, proof, "Proof should be nil for nil destination public key")
	})

	t.Run("Invalid Source Ciphertext", func(t *testing.T) {
		// Source ciphertext is nil
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			&destinationKeypair.PublicKey,
			nil,
			&destinationRandomness,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil source ciphertext")
		require.Nil(t, proof, "Proof should be nil")
	})

	t.Run("Invalid Destination Randomness", func(t *testing.T) {
		// Destination randomness is nil
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			nil,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil destination randomness")
		require.Nil(t, proof, "Proof should be nil")
	})

	t.Run("Invalid Amount", func(t *testing.T) {
		// Amount is nil
		proof, err := NewCiphertextCiphertextEqualityProof(
			sourceKeypair,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			&destinationRandomness,
			nil,
		)
		require.Error(t, err, "Proof generation should fail for nil amount")
		require.Nil(t, proof, "Proof should be nil")
	})

}

// Invalid input tests for VerifyCiphertextCiphertextEquality
func TestVerifyCiphertextCiphertextEquality_InvalidInputs(t *testing.T) {
	sourcePrivateKey, _ := testutils.GenerateKey()
	destPrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)
	destinationKeypair, _ := eg.KeyGen(*destPrivateKey, TestDenom)

	amount := big.NewInt(100)

	// Encrypt the amount using source and destination public keys
	sourceCiphertext, _, _ := eg.Encrypt(sourceKeypair.PublicKey, amount)
	_, destinationRandomness, _ := eg.Encrypt(destinationKeypair.PublicKey, amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	proof, _ := NewCiphertextCiphertextEqualityProof(
		sourceKeypair,
		&destinationKeypair.PublicKey,
		sourceCiphertext,
		&destinationRandomness,
		&scalarAmount,
	)

	t.Run("Invalid Proof", func(t *testing.T) {
		// Proof is nil
		valid := VerifyCiphertextCiphertextEquality(
			nil,
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			sourceCiphertext,
		)
		require.False(t, valid, "Proof verification should fail for nil proof")
	})

	t.Run("Invalid Proof with nil fields", func(t *testing.T) {
		// Proof is nil
		valid := VerifyCiphertextCiphertextEquality(
			&CiphertextCiphertextEqualityProof{},
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			sourceCiphertext,
		)
		require.False(t, valid, "Proof verification should fail for nil proof")
	})

	t.Run("Invalid Source Public Key", func(t *testing.T) {
		// Source public key is nil
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			nil,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			sourceCiphertext,
		)
		require.False(t, valid, "Proof verification should fail for nil source public key")
	})

	t.Run("Invalid Destination Public Key", func(t *testing.T) {
		// Destination public key is nil
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			&sourceKeypair.PublicKey,
			nil,
			sourceCiphertext,
			sourceCiphertext,
		)
		require.False(t, valid, "Proof verification should fail for nil destination public key")
	})

	t.Run("Invalid Source Ciphertext", func(t *testing.T) {
		// Source ciphertext is nil
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			nil,
			sourceCiphertext,
		)
		require.False(t, valid, "Proof verification should fail for nil source ciphertext")
	})

	t.Run("Invalid Destination Ciphertext", func(t *testing.T) {
		// Destination ciphertext is nil
		valid := VerifyCiphertextCiphertextEquality(
			proof,
			&sourceKeypair.PublicKey,
			&destinationKeypair.PublicKey,
			sourceCiphertext,
			nil,
		)
		require.False(t, valid, "Proof verification should fail for nil destination ciphertext")
	})
}
