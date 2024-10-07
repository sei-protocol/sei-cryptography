package encryption

import (
	"testing"

	"crypto/ecdsa"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

// GenerateKey generates a new private key we can use for testing.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func TestAESKeyGeneration(t *testing.T) {
	privateKey, err := GenerateKey()
	require.Nil(t, err, "Should not have error here")

	denom := "factory/sei1239081236470/testToken"
	aesPK, err := GetAesKey(*privateKey, denom)
	require.Nil(t, err, "Should not have error here")

	// Test that aesPK is deterministically generated
	aesPKAgain, err := GetAesKey(*privateKey, denom)
	require.Equal(t, aesPK, aesPKAgain, "PK should be deterministically generated")

	// Test that changing the salt should generate a different key
	altDenom := "factory/sei1239081236470/testToken1"
	aesPKDiffSalt, err := GetAesKey(*privateKey, altDenom)
	require.NotEqual(t, aesPK, aesPKDiffSalt, "PK should different for different salt")

	// Test same thing for salt of same length
	altDenom = "factory/sei1239081236470/testTokeN"
	aesPKDiffSalt, err = GetAesKey(*privateKey, altDenom)
	require.NotEqual(t, aesPK, aesPKDiffSalt, "PK should different for different salt")

	// Test that different privateKey should generate different PK
	altPrivateKey, err := GenerateKey()
	require.Nil(t, err, "Should not have error here")
	aesPKDiffPK, err := GetAesKey(*altPrivateKey, altDenom)
	require.NotEqual(t, aesPK, aesPKDiffPK, "PK should different for different ESDCA Private Key")
}

func TestAesEncryptionDecryption(t *testing.T) {
	key := []byte("examplekey12345678901234567890ab")        // 32 bytes for AES-256
	anotherKey := []byte("randomkey12345678901234567890abc") // 32 bytes for AES-256

	value := uint64(3023)

	// Encrypt the plaintext
	encrypted, err := EncryptAESGCM(value, key)
	require.Nil(t, err, "Should have no error encrypting")

	// Decrypt the ciphertext
	decrypted, err := DecryptAESGCM(encrypted, key)
	require.Nil(t, err, "Should have no error decrypting")
	require.Equal(t, value, decrypted)

	// Encrypt the plaintext again. This should produce a different ciphertext.
	encryptedAgain, err := EncryptAESGCM(value, key)
	require.Nil(t, err, "Should have no error encrypting")
	require.NotEqual(t, encrypted, encryptedAgain)

	// Encrypt the plaintext again using a different key. This should produce a different ciphertext.
	encryptedAgain, err = EncryptAESGCM(value, anotherKey)
	require.Nil(t, err, "Should have no error encrypting")
	require.NotEqual(t, encrypted, encryptedAgain)

	// Test that decryption with the wrong key will yield an error.
	decryptedWrongly, err := DecryptAESGCM(encryptedAgain, key)
	require.Empty(t, decryptedWrongly)
	require.Error(t, err, "Should have an error decrypting")
}
