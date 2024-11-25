package zkproofs

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/require"
)

func TestValidityProof(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	altPrivateKey, _ := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, TestDenom)

	message12 := big.NewInt(12)
	ciphertext12, randomness12, err := eg.Encrypt(keys.PublicKey, message12)
	require.Nil(t, err)

	proof12, err := NewCiphertextValidityProof(&randomness12, keys.PublicKey, ciphertext12, message12)
	require.Nil(t, err)

	validated := VerifyCiphertextValidity(proof12, keys.PublicKey, ciphertext12)
	require.True(t, validated, "Validating with the correct parameters should validate as true")

	validated = VerifyCiphertextValidity(proof12, altKeys.PublicKey, ciphertext12)
	require.False(t, validated, "Validating with the wrong PublicKey should validate as false")

	// Encrypt a message (e.g., x = 42)
	message42 := big.NewInt(42)
	ciphertext42, randomness42, _ := eg.Encrypt(keys.PublicKey, message42)

	validated = VerifyCiphertextValidity(proof12, altKeys.PublicKey, ciphertext42)
	require.False(t, validated, "Validating with the wrong ciphertext should validate as false")

	// Generate proof using the wrong pubkey
	wrongProof, err := NewCiphertextValidityProof(&randomness12, altKeys.PublicKey, ciphertext12, message12)
	require.Nil(t, err)
	validated = VerifyCiphertextValidity(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong PublicKey should validate as false")

	validated = VerifyCiphertextValidity(wrongProof, altKeys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong PublicKey should validate as false even"+
		" when using the same pubkey to validate")

	// Generate proof using the wrong randomness
	wrongProof, err = NewCiphertextValidityProof(&randomness42, keys.PublicKey, ciphertext12, message12)
	require.Nil(t, err)
	validated = VerifyCiphertextValidity(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong randomness should validate as false")

	// Generate proof with the wrong ciphertext
	wrongProof, err = NewCiphertextValidityProof(&randomness42, keys.PublicKey, ciphertext12, message42)
	require.Nil(t, err)
	validated = VerifyCiphertextValidity(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong ciphertext should validate as false")
}

func TestCiphertextValidityProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	message12 := big.NewInt(12)
	ciphertext12, randomness12, _ := eg.Encrypt(keys.PublicKey, message12)

	original, err := NewCiphertextValidityProof(&randomness12, keys.PublicKey, ciphertext12, message12)
	require.NoError(t, err, "Proof generation should not produce an error")
	// Marshal the proof to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a CiphertextValidityProof
	var unmarshaled CiphertextValidityProof
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	// Compare the original and unmarshaled proof
	require.True(t, original.Commitment1.Equal(unmarshaled.Commitment1), "Commitment1 points should be equal")
	require.True(t, original.Commitment2.Equal(unmarshaled.Commitment2), "Commitment2 points should be equal")
	require.Equal(t, original.Response1, unmarshaled.Response1, "Response1 scalars should be equal")
	require.Equal(t, original.Response2, unmarshaled.Response2, "Response2 scalars should be equal")
}

func TestNewCiphertextValidityProof_InvalidInput(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	amount := big.NewInt(100)
	// Encrypt the amount using source and destination public keys
	ciphertext, randomness, _ := eg.Encrypt(keys.PublicKey, amount)

	t.Run("Invalid Source Randomness", func(t *testing.T) {
		// Source randomness is nil
		proof, err := NewCiphertextValidityProof(
			nil,
			keys.PublicKey,
			ciphertext,
			amount,
		)
		require.Nil(t, proof, "Proof should be nil for nil source randomness")
		require.Error(t, err, "Proof generation should fail for nil source randomness")
	})

	t.Run("Invalid Source PublicKey", func(t *testing.T) {
		// Source public key is nil
		proof, err := NewCiphertextValidityProof(
			&randomness,
			nil,
			ciphertext,
			amount,
		)
		require.Nil(t, proof, "Proof should be nil for nil source public key")
		require.Error(t, err, "Proof generation should fail for nil source public key")
	})

	t.Run("Invalid Source Ciphertext", func(t *testing.T) {
		// Source ciphertext is nil
		proof, err := NewCiphertextValidityProof(
			&randomness,
			keys.PublicKey,
			nil,
			amount,
		)
		require.Nil(t, proof, "Proof should be nil for nil source ciphertext")
		require.Error(t, err, "Proof generation should fail for nil source ciphertext")
	})
}

func TestVerifyCiphertextValidityProof_Invalid_Input(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	amount := big.NewInt(100)
	// Encrypt the amount using source and destination public keys
	ciphertext, randomness, _ := eg.Encrypt(keys.PublicKey, amount)

	proof, _ := NewCiphertextValidityProof(&randomness, keys.PublicKey, ciphertext, amount)

	t.Run("Invalid (nil) proof", func(t *testing.T) {
		// Proof commitment1 is nil
		validated := VerifyCiphertextValidity(nil, keys.PublicKey, ciphertext)
		require.False(t, validated, "Validation should fail for nil commitment1")
	})

	t.Run("Invalid proof with nil fields", func(t *testing.T) {
		validated := VerifyCiphertextValidity(&CiphertextValidityProof{}, keys.PublicKey, ciphertext)
		require.False(t, validated, "Validation should fail for proof with nil fields")
	})

	t.Run("Invalid Public Key", func(t *testing.T) {
		// Proof challenge is nil
		validated := VerifyCiphertextValidity(proof, nil, ciphertext)
		require.False(t, validated, "Validation should fail for nil challenge")
	})

	t.Run("Invalid Ciphertext", func(t *testing.T) {
		// Proof response1 is nil
		validated := VerifyCiphertextValidity(proof, keys.PublicKey, nil)
		require.False(t, validated, "Validation should fail for nil response1")
	})
}
