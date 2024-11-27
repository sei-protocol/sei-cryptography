package zkproofs

import (
	"encoding/json"
	"testing"

	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/require"
)

func TestPubKeyValidityProof(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	altPrivateKey, _ := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, TestDenom)

	// Prove knowledge of the private key
	proof, err := NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)
	require.NoError(t, err)

	// Verify the proof
	valid := VerifyPubKeyValidity(keys.PublicKey, proof)
	require.True(t, valid, "Valid Proof should be validated as true")

	invalid := VerifyPubKeyValidity(altKeys.PublicKey, proof)
	require.False(t, invalid, "Proof should be invalid when trying to validate wrong PublicKey")

	// Generate proof with the wrong private key.
	badProof, err := NewPubKeyValidityProof(keys.PublicKey, altKeys.PrivateKey)
	require.Nil(t, err)
	invalid = VerifyPubKeyValidity(keys.PublicKey, badProof)
	require.False(t, invalid, "Proof generated with wrong Privkey should be validated as false.")
}

func TestPubKeyValidityProof_MarshalUnmarshalJSON(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	original, err := NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)
	require.NoError(t, err, "Proof generation should not produce an error")
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

func TestNewPubKeyValidityProof_InvalidInput(t *testing.T) {
	privateKey, _ := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	keys, _ := eg.KeyGen(*privateKey, TestDenom)

	_, err := NewPubKeyValidityProof(nil, keys.PrivateKey)
	require.Error(t, err, "Generating proof with nil public key should produce an error")

	_, err = NewPubKeyValidityProof(keys.PublicKey, nil)
	require.Error(t, err, "Generating proof with nil private key should produce an error")
}

func TestVerifyPubKeyValidityProof_InvalidInput(t *testing.T) {
	privateKey, err := testutils.GenerateKey()
	require.Nil(t, err)

	eg := elgamal.NewTwistedElgamal()
	keys, err := eg.KeyGen(*privateKey, TestDenom)
	require.Nil(t, err)

	// Prove knowledge of the private key
	proof, err := NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)
	require.Nil(t, err)

	// Verify the proof
	valid := VerifyPubKeyValidity(nil, proof)
	require.False(t, valid, "proof verification should fail for nil public key")

	invalidProof := PubKeyValidityProof{}

	valid = VerifyPubKeyValidity(keys.PublicKey, &invalidProof)
	require.False(t, valid, "proof verification should fail for invalid proof")
}
