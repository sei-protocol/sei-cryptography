package elgamal

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func TestKeyGeneration(t *testing.T) {
	privateKey, err := GenerateKey()
	require.Nil(t, err)

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)

	denom := "factory/sei1239081236470/testToken"
	keyPair, err := eg.KeyGen(*privateKey, denom)
	require.Nil(t, err)

	// Test that keyPair is deterministically generated
	keyPairAgain, err := eg.KeyGen(*privateKey, denom)
	require.Nil(t, err)
	require.Equal(t, keyPair, keyPairAgain, "PK should be deterministically generated")

	// Test that changing the salt should generate a different key
	altDenom := "factory/sei1239081236470/testToken1"
	keyPairDiffSalt, err := eg.KeyGen(*privateKey, altDenom)
	require.Nil(t, err)
	require.NotEqual(t, keyPair, keyPairDiffSalt, "PK should be different for different salt")

	// Test same thing for salt of same length
	altDenom = "factory/sei1239081236470/testTokeN"
	keyPairDiffSalt, err = eg.KeyGen(*privateKey, altDenom)
	require.Nil(t, err)
	require.NotEqual(t, keyPair, keyPairDiffSalt, "PK should be different for different salt")

	// Test that different privateKey should generate different PK
	altPrivateKey, err := GenerateKey()
	require.Nil(t, err)
	keyPairDiffPK, err := eg.KeyGen(*altPrivateKey, altDenom)
	require.Nil(t, err)
	require.NotEqual(t, keyPair, keyPairDiffPK, "PK should be different for different ESDCA Private Key")
}

func TestEncryptionDecryption(t *testing.T) {
	privateKey, _ := GenerateKey()
	altPrivateKey, _ := GenerateKey()

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)

	denom := "factory/sei1239081236470/testToken"

	keys, _ := eg.KeyGen(*privateKey, denom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, denom)

	// Happy Path
	value := 108
	ciphertext, _, err := eg.Encrypt(keys.PublicKey, uint64(value))
	require.Nil(t, err, "Should have no error while encrypting")

	decrypted, err := eg.Decrypt(keys.PrivateKey, ciphertext, MaxBits16)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, *decrypted, "Should have the same value")

	decrypted, err = eg.Decrypt(keys.PrivateKey, ciphertext, MaxBits32)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, *decrypted, "Should have the same value")

	// Using a different private key to decrypt should yield an error.
	decryptedWrongly, err := eg.Decrypt(altKeys.PrivateKey, ciphertext, MaxBits32)
	require.Nil(t, decryptedWrongly)
	require.Error(t, err, "Should be unable to decrypt using the wrong private key")

	// Test overflow behavior
	ciphertextOverflow, _, err := eg.Encrypt(keys.PublicKey, math.MaxUint64)
	require.Nil(t, err, "Should have no error while encrypting")
	decryptedOverflow, err := eg.Decrypt(keys.PrivateKey, ciphertextOverflow, MaxBits32)
	require.Nil(t, decryptedOverflow)
	require.Error(t, err, "Should be unable to decrypt the invalid overflow value")
}

// Due to the size of 48 bit numbers, this test takes a really long time (~1hr) to run.
func Test48BitEncryptionDecryption(t *testing.T) {
	privateKey, err := GenerateKey()
	require.Nil(t, err)
	denom := "factory/sei1239081236470/testToken"

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)
	keys, _ := eg.KeyGen(*privateKey, denom)

	// First decrypt a 32 bit number (sets up the decryptor for a later test)
	value := 108092
	ciphertext, _, err := eg.Encrypt(keys.PublicKey, uint64(value))
	require.Nil(t, err, "Should have no error while encrypting")

	decrypted, err := eg.DecryptLargeNumber(keys.PrivateKey, ciphertext, MaxBits48)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, *decrypted, "Should have the same value")

	// Create a large <48 bit number to be encrypted.
	largeValue := 1 << 39
	largeCiphertext, _, err := eg.Encrypt(keys.PublicKey, uint64(largeValue))
	require.Nil(t, err, "Should have no error while encrypting")

	largeDecrypted, err := eg.DecryptLargeNumber(keys.PrivateKey, largeCiphertext, MaxBits48)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, largeValue, *largeDecrypted, "Should have the same value")

	// Attempting to decrypt with the wrong max bits set should yield an error.
	decryptedWrongly, err := eg.DecryptLargeNumber(keys.PrivateKey, largeCiphertext, MaxBits32)
	require.Nil(t, decryptedWrongly)
	require.Error(t, err, "Should be unable to decrypt using the wrong maxBits")

	// Decrypting the 48 bit value should not corrupt the map for 32 bit values.
	decrypted, err = eg.DecryptLargeNumber(keys.PrivateKey, ciphertext, MaxBits32)
	require.Nil(t, err, "Should still have no error while decrypting")
	require.Equal(t, value, *decrypted, "Should still have the same value")
}

func TestAddCiphertext(t *testing.T) {
	privateKey, _ := GenerateKey()
	altPrivateKey, _ := GenerateKey()

	denom := "factory/sei1239081236470/testToken"

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)

	keys, _ := eg.KeyGen(*privateKey, denom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, denom)

	// Happy Path
	value1 := 30842
	ciphertext1, _, err := eg.Encrypt(keys.PublicKey, uint64(value1))
	require.Nil(t, err, "Should have no error while encrypting")

	value2 := 1901
	ciphertext2, _, err := eg.Encrypt(keys.PublicKey, uint64(value2))
	require.Nil(t, err, "Should have no error while encrypting")

	ciphertextSum, err := AddCiphertext(ciphertext1, ciphertext2)
	require.Nil(t, err, "Should have no error while adding ciphertexts")

	decrypted, err := eg.Decrypt(keys.PrivateKey, ciphertextSum, MaxBits32)
	require.Nil(t, err, "Should have no error while decrypting")
	require.NotNil(t, decrypted)
	require.Equal(t, value1+value2, *decrypted, "Decrypted sum should be correct")

	// Test that the add operation is commutative by adding in the other order.
	ciphertextSumInv, err := AddCiphertext(ciphertext2, ciphertext1)
	require.Nil(t, err, "Should have no error while adding ciphertexts")
	require.Equal(t, ciphertextSum, ciphertextSumInv, "Summation is a deterministic operation. Both ciphertexts should be the same")

	// Test addition of 2 ciphertexts encoded with different public keys.
	ciphertext2alt, _, err := eg.Encrypt(altKeys.PublicKey, uint64(value2))
	require.Nil(t, err, "Should have no error while encrypting")

	// Even though ciphertexts were encoded using different keys, addition doesn't throw an error.
	// However, the resulting ciphertext is unlikely to be decodable.
	ciphertextSum, err = AddCiphertext(ciphertext1, ciphertext2alt)
	require.Nil(t, err, "Even though ciphertexts were encoded using different keys, addition doesn't throw an error.")

	decrypted, err = eg.Decrypt(keys.PrivateKey, ciphertextSum, MaxBits32)
	require.Nil(t, decrypted)
	require.Error(t, err, "Ciphertext should be undecodable using either private key")

	decrypted, err = eg.Decrypt(altKeys.PrivateKey, ciphertextSum, MaxBits32)
	require.Nil(t, decrypted)
	require.Error(t, err, "Ciphertext should be undecodable using either private key")
}
