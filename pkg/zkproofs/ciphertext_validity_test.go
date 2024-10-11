package zkproofs

import (
	"encoding/json"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidityProof(t *testing.T) {
	privateKey, err := elgamal.GenerateKey()
	altPrivateKey, err := elgamal.GenerateKey()

	require.Nil(t, err, "Should not have error here")

	eg := elgamal.NewTwistedElgamal()
	keys, err := eg.KeyGen(*privateKey, TestDenom)
	altKeys, err := eg.KeyGen(*altPrivateKey, TestDenom)

	message12 := uint64(12)
	ciphertext12, randomness12, err := eg.Encrypt(keys.PublicKey, message12)
	require.Nil(t, err, "Should not have error here")

	proof12 := NewCiphertextValidityProof(message12, &randomness12, keys.PublicKey, ciphertext12)

	validated := VerifyCiphertextValidityProof(proof12, keys.PublicKey, ciphertext12)
	require.True(t, validated, "Validating with the correct parameters should validate as true")

	validated = VerifyCiphertextValidityProof(proof12, altKeys.PublicKey, ciphertext12)
	require.False(t, validated, "Validating with the wrong PublicKey should validate as false")

	// Encrypt a message (e.g., x = 42)
	message42 := uint64(42)
	ciphertext42, randomness42, _ := eg.Encrypt(keys.PublicKey, message42)

	validated = VerifyCiphertextValidityProof(proof12, altKeys.PublicKey, ciphertext42)
	require.False(t, validated, "Validating with the wrong ciphertext should validate as false")

	// Generate proof using the wrong pubkey
	wrongProof := NewCiphertextValidityProof(message12, &randomness12, altKeys.PublicKey, ciphertext12)
	validated = VerifyCiphertextValidityProof(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong PublicKey should validate as false")

	validated = VerifyCiphertextValidityProof(wrongProof, altKeys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong PublicKey should validate as false even"+
		" when using the same pubkey to validate")

	// Generate proof using the wrong randomness
	wrongProof = NewCiphertextValidityProof(message12, &randomness42, keys.PublicKey, ciphertext12)
	validated = VerifyCiphertextValidityProof(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong randomness should validate as false")

	// Generate proof with the wrong ciphertext
	wrongProof = NewCiphertextValidityProof(message42, &randomness42, keys.PublicKey, ciphertext12)
	validated = VerifyCiphertextValidityProof(wrongProof, keys.PublicKey, ciphertext12)
	require.False(t, validated, "Proof generated with the wrong ciphertext should validate as false")
}

func TestCiphertextValidityProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey, _ := elgamal.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	message12 := uint64(12)
	ciphertext12, randomness12, _ := eg.Encrypt(keys.PublicKey, message12)

	original := NewCiphertextValidityProof(message12, &randomness12, keys.PublicKey, ciphertext12)
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
	require.Equal(t, original.Challenge, unmarshaled.Challenge, "Challenge scalars should be equal")
	require.Equal(t, original.Response1, unmarshaled.Response1, "Response1 scalars should be equal")
	require.Equal(t, original.Response2, unmarshaled.Response2, "Response2 scalars should be equal")
}
