package elgamal

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCiphertext_MarshalJSON(t *testing.T) {
	privateKey, _ := generateKey()
	eg := NewTwistedElgamal()

	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	value := uint64(108)
	ciphertext, _, _ := eg.Encrypt(keys.PublicKey, value)

	// Marshal the Ciphertext to JSON
	data, err := json.Marshal(ciphertext)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a Ciphertext
	var unmarshaled Ciphertext
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	// Compare the original and unmarshaled Ciphertext
	require.True(t, ciphertext.C.Equal(unmarshaled.C), "C points should be equal")
	require.True(t, ciphertext.D.Equal(unmarshaled.D), "D points should be equal")

}
