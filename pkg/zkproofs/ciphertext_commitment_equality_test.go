package zkproofs

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertextCommitmentEqualityProof(t *testing.T) {
	tests := []struct {
		name                          string
		sourceAmount                  *big.Int
		alternativePedersenCommitment bool
		incorrectPedersenOpening      bool
		incorrectAmount               bool
		expectValid                   bool
	}{
		{
			name:                          "Valid Proof - Equal Amounts and Commitments",
			sourceAmount:                  big.NewInt(100),
			alternativePedersenCommitment: false,
			expectValid:                   true,
		},
		{
			name:                          "Valid Proof - Equal Amounts and Alternative Commitments",
			sourceAmount:                  big.NewInt(100),
			alternativePedersenCommitment: true,
			expectValid:                   true,
		},
		{
			name:                          "Invalid Proof - Different Pedersen Opening",
			sourceAmount:                  big.NewInt(200),
			alternativePedersenCommitment: false,
			incorrectPedersenOpening:      true,
			expectValid:                   false,
		},
		{
			name:                          "Invalid Proof - Incorrect Amount in Pedersen Commitment",
			sourceAmount:                  big.NewInt(200),
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
			sourcePrivateKey, _ := testutils.GenerateKey()
			eg := elgamal.NewTwistedElgamal()
			sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

			// Encrypt the source amount
			sourceCiphertext, sourceRandomness, err := eg.Encrypt(sourceKeypair.PublicKey, tt.sourceAmount)
			assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

			amountToSet := new(big.Int)
			if tt.incorrectAmount {
				amountToSet = amountToSet.Add(tt.sourceAmount, big.NewInt(1))
			} else {
				amountToSet = tt.sourceAmount
			}
			scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amountToSet)

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
	sourcePrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

	amount := big.NewInt(232436)
	// Encrypt the source amount
	sourceCiphertext, sourceRandomness, err := eg.Encrypt(sourceKeypair.PublicKey, amount)
	assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	// Create a sample CiphertextCommitmentEqualityProof
	proof, err := NewCiphertextCommitmentEqualityProof(
		sourceKeypair,
		sourceCiphertext,
		&sourceRandomness,
		&scalarAmount,
	)

	require.NoError(t, err, "Proof generation should not fail")

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

func TestNewCiphertextCommitmentEqualityProof_InvalidInput(t *testing.T) {
	sourcePrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

	amount := big.NewInt(100)

	// Encrypt the amount using source and destination public keys
	sourceCiphertext, sourceRandomness, _ := eg.Encrypt(sourceKeypair.PublicKey, amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	t.Run("Invalid Source Keypair", func(t *testing.T) {
		// Source keypair is nil
		proof, err := NewCiphertextCommitmentEqualityProof(
			nil,
			sourceCiphertext,
			&sourceRandomness,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil source keypair")
		require.Nil(t, proof, "Proof should be nil for nil source keypair")
	})

	t.Run("Invalid Source Ciphertext", func(t *testing.T) {
		// Source ciphertext is nil
		proof, err := NewCiphertextCommitmentEqualityProof(
			sourceKeypair,
			nil,
			&sourceRandomness,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil source ciphertext")
		require.Nil(t, proof, "Proof should be nil for nil source ciphertext")
	})

	t.Run("Invalid Source Pedersen opening", func(t *testing.T) {
		// Source Pedersen Opening is nil
		proof, err := NewCiphertextCommitmentEqualityProof(
			sourceKeypair,
			sourceCiphertext,
			nil,
			&scalarAmount,
		)
		require.Error(t, err, "Proof generation should fail for nil Pedersen opening")
		require.Nil(t, proof, "Proof should be nil")
	})

	t.Run("Invalid Amount", func(t *testing.T) {
		// Amount is nil
		proof, err := NewCiphertextCommitmentEqualityProof(
			sourceKeypair,
			sourceCiphertext,
			&sourceRandomness,
			nil,
		)
		require.Error(t, err, "Proof generation should fail for nil amount")
		require.Nil(t, proof, "Proof should be nil")
	})
}

func TestVerifyCiphertextCommitmentEquality_InvalidInput(t *testing.T) {
	sourcePrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

	amount := big.NewInt(100)

	// Encrypt the amount using source and destination public keys
	sourceCiphertext, sourceRandomness, _ := eg.Encrypt(sourceKeypair.PublicKey, amount)
	scalarAmount, _ := curves.ED25519().Scalar.SetBigInt(amount)

	// Generate the proof
	proof, _ := NewCiphertextCommitmentEqualityProof(
		sourceKeypair,
		sourceCiphertext,
		&sourceRandomness,
		&scalarAmount,
	)

	t.Run("Invalid Proof", func(t *testing.T) {
		// Proof is nil
		valid := VerifyCiphertextCommitmentEquality(
			nil,
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for nil proof")
	})

	t.Run("Invalid Proof With nil fields", func(t *testing.T) {
		// Proof is nil
		valid := VerifyCiphertextCommitmentEquality(
			&CiphertextCommitmentEqualityProof{},
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for proof with nil fields")
	})

	t.Run("Invalid Proof Params", func(t *testing.T) {
		// Y2 is zero point
		clone := *proof
		clone.Y2 = curves.ED25519().NewIdentityPoint()
		valid := VerifyCiphertextCommitmentEquality(
			&clone,
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for proof params with zero value")

		clone = *proof
		clone.Zx = curves.ED25519().Scalar.Zero()
		valid = VerifyCiphertextCommitmentEquality(
			&clone,
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for proof params with zero value")

		clone = *proof
		clone.Y1 = nil
		valid = VerifyCiphertextCommitmentEquality(
			&clone,
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for proof params with zero value")
	})

	t.Run("Invalid Source Public Key", func(t *testing.T) {
		// Source public key is nil
		valid := VerifyCiphertextCommitmentEquality(
			proof,
			nil,
			sourceCiphertext,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for nil source public key")
	})

	t.Run("Invalid Source Ciphertext", func(t *testing.T) {
		// Source ciphertext is nil
		valid := VerifyCiphertextCommitmentEquality(
			proof,
			&sourceKeypair.PublicKey,
			nil,
			&sourceCiphertext.C,
		)
		require.False(t, valid, "Proof verification should fail for nil source ciphertext")
	})

	t.Run("Invalid Pedersen Commitment", func(t *testing.T) {
		// Pedersen commitment is nil
		valid := VerifyCiphertextCommitmentEquality(
			proof,
			&sourceKeypair.PublicKey,
			sourceCiphertext,
			nil,
		)
		require.False(t, valid, "Proof verification should fail for nil Pedersen commitment")
	})
}

// Test that the proof is still valid for cases where Ciphertext.D is the identity point.
func TestCiphertextCommitmentEqualityProof_IdentityD(t *testing.T) {
	// Key generation
	sourcePrivateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	sourceKeypair, _ := eg.KeyGen(*sourcePrivateKey, TestDenom)

	// Encrypt the source amount
	sourceCiphertext, _, err := eg.Encrypt(sourceKeypair.PublicKey, big.NewInt(100))
	assert.NoError(t, err, "Encryption should succeed for sourceCiphertext")

	zeroCommitment, zeroRandomness, _ := eg.Encrypt(sourceKeypair.PublicKey, big.NewInt(0))
	zeroCiphertext, _ := elgamal.SubtractCiphertext(sourceCiphertext, sourceCiphertext)
	zeroScalar := curves.ED25519().Scalar.Zero()
	// Generate the proof
	proof, err := NewCiphertextCommitmentEqualityProof(
		sourceKeypair,
		zeroCiphertext,
		&zeroRandomness,
		&zeroScalar,
	)
	assert.NoError(t, err, "Proof generation should not fail")

	// VerifyCipherCipherEquality the proof
	valid := VerifyCiphertextCommitmentEquality(
		proof,
		&sourceKeypair.PublicKey,
		zeroCiphertext,
		&zeroCommitment.C,
	)
	assert.True(t, valid, "Proof verification should not fail")
}
