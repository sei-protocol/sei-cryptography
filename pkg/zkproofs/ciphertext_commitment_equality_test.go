package zkproofs

import (
	"crypto/rand"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestCiphertextCommitmentEqualityProof(t *testing.T) {
	tests := []struct {
		name                          string
		sourceAmount                  uint64
		alternativePedersenCommitment bool
		incorrectPedersenOpening      bool
		incorrectAmount               bool
		expectValid                   bool
	}{
		{
			name:                          "Valid Proof - Equal Amounts and Commitments",
			sourceAmount:                  100,
			alternativePedersenCommitment: false,
			expectValid:                   true,
		},
		{
			name:                          "Valid Proof - Equal Amounts and Alternative Commitments",
			sourceAmount:                  100,
			alternativePedersenCommitment: true,
			expectValid:                   true,
		},
		{
			name:                          "Invalid Proof - Different Pedersen Opening",
			sourceAmount:                  200,
			alternativePedersenCommitment: false,
			incorrectPedersenOpening:      true,
			expectValid:                   false,
		},
		{
			name:                          "Invalid Proof - Incorrect Amount in Pedersen Commitment",
			sourceAmount:                  200,
			alternativePedersenCommitment: true,
			incorrectPedersenOpening:      false,
			incorrectAmount:               true,
			expectValid:                   false,
		},
	}
	for _, tt := range tests {
		tt := tt // Capture range variable
		t.Run(tt.name, func(t *testing.T) {
			// Key generation
			sourcePrivateKey, err := elgamal.GenerateKey()
			eg := elgamal.NewTwistedElgamal()
			sourceKeypair, err := eg.KeyGen(*sourcePrivateKey, TestDenom)

			// Encrypt the source amount
			sourceCiphertext, sourceRandomness, err := eg.Encrypt(sourceKeypair.PublicKey, tt.sourceAmount)
			assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

			var amountToSet uint64
			if tt.incorrectAmount {
				amountToSet = tt.sourceAmount + 1
			} else {
				amountToSet = tt.sourceAmount
			}
			scalarAmtValue := new(big.Int).SetUint64(amountToSet)
			scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(scalarAmtValue)

			pedersenCommitment := sourceCiphertext.C

			if !tt.alternativePedersenCommitment {
				// Generate a random scalar r
				randomFactor := curves.ED25519().Scalar.Random(rand.Reader)

				// Fixed base points G and H
				G := eg.GetG()
				H := eg.GetH()
				// Compute the Pedersen commitment: C = r * H + x * G
				rH := H.Mul(randomFactor) // r * H
				xG := G.Mul(scalarAmount) // x * G
				C := rH.Add(xG)

				pedersenCommitment = C
				sourceRandomness = randomFactor
			}

			if tt.incorrectPedersenOpening {
				// Generate a random scalar r
				randomFactor := curves.ED25519().Scalar.Random(rand.Reader)
				sourceRandomness = randomFactor
			}

			// Generate the proof
			proof, err := NewCiphertextCommitmentEqualityProof(
				sourceKeypair,
				sourceCiphertext,
				&sourceRandomness,
				&scalarAmount,
			)
			assert.NoError(t, err, "Proof generation should not fail")

			// VerifyCipherCipherEquality the proof
			valid := VerifyCiphertextCommitmentEquality(
				proof,
				&sourceKeypair.PublicKey,
				sourceCiphertext,
				&pedersenCommitment,
			)

			if tt.expectValid {
				assert.True(t, valid, "Proof verification should succeed")
			} else {
				assert.False(t, valid, "Proof verification should fail")
			}
		})
	}
}

func TestCiphertextCommitmentEqualityProof_MarshalUnmarshalJSON(t *testing.T) {
	sourcePrivateKey, _ := elgamal.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

	amount := uint64(232436)
	// Encrypt the source amount
	sourceCiphertext, sourceRandomness, err := eg.Encrypt(sourceKeypair.PublicKey, amount)
	assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

	scalarAmtValue := new(big.Int).SetUint64(amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(scalarAmtValue)

	// Create a sample CiphertextCommitmentEqualityProof
	proof, err := NewCiphertextCommitmentEqualityProof(
		sourceKeypair,
		sourceCiphertext,
		&sourceRandomness,
		&scalarAmount,
	)

	// Marshal the proof to JSON
	data, err := json.Marshal(proof)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a CiphertextCommitmentEqualityProof
	var unmarshaled CiphertextCommitmentEqualityProof
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	// Compare the original and unmarshaled proof
	require.True(t, proof.Y0.Equal(unmarshaled.Y0), "Y0 points should be equal")
	require.True(t, proof.Y1.Equal(unmarshaled.Y1), "Y1 points should be equal")
	require.True(t, proof.Y2.Equal(unmarshaled.Y2), "Y2 points should be equal")
	require.Equal(t, proof.Zs, unmarshaled.Zs, "Zs scalars should be equal")
	require.Equal(t, proof.Zx, unmarshaled.Zx, "Zx scalars should be equal")
	require.Equal(t, proof.Zr, unmarshaled.Zr, "Zr scalars should be equal")
}
