package zkproofs

import (
	"encoding/json"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPubKeyValidityProof(t *testing.T) {
	privateKey, err := elgamal.GenerateKey()
	altPrivateKey, err := elgamal.GenerateKey()

	require.Nil(t, err, "Should not have error here")

	eg := elgamal.NewTwistedElgamal()
	keys, err := eg.KeyGen(*privateKey, TestDenom)
	altKeys, err := eg.KeyGen(*altPrivateKey, TestDenom)
	require.Nil(t, err, "Should not have error here")

	// Prove knowledge of the private key
	proof := NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)

	// Verify the proof
	valid := ValidatePubKeyValidityProof(keys.PublicKey, *proof)
	require.True(t, valid, "Valid Proof should be validated as true")

	invalid := ValidatePubKeyValidityProof(altKeys.PublicKey, *proof)
	require.False(t, invalid, "Proof should be invalid when trying to validate wrong PublicKey")

	// Generate proof with the wrong private key.
	badProof := NewPubKeyValidityProof(keys.PublicKey, altKeys.PrivateKey)
	invalid = ValidatePubKeyValidityProof(keys.PublicKey, *badProof)
	require.False(t, invalid, "Proof generated with wrong Privkey should be validated as false.")
}

func TestPubKeyValidityProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey, _ := elgamal.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	original := NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)
	// Marshal the proof to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a PubKeyValidityProof
	var unmarshaled PubKeyValidityProof
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	// Compare the original and unmarshaled proof
	require.True(t, original.Y.Equal(unmarshaled.Y), "Y points should be equal")
	require.Equal(t, original.Z, unmarshaled.Z, "Z scalars should be equal")
}
