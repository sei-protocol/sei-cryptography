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

const DefaultTestDenom = "factory/sei1239081236472sd/testToken"

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func TestKeyGeneration(t *testing.T) {
	privateKey, err := GenerateKey()
	require.Nil(t, err)

	eg := NewTwistedElgamalWithED25519Curve()
	keyPair, err := eg.KeyGen(*privateKey, DefaultTestDenom)
	require.Nil(t, err)

	// Test that keyPair is deterministically generated
	keyPairAgain, err := eg.KeyGen(*privateKey, DefaultTestDenom)
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

	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, DefaultTestDenom)

	// Happy Path
	value := uint64(108)
	ciphertext, _, err := eg.Encrypt(keys.PublicKey, value)
	require.Nil(t, err, "Should have no error while encrypting")

	decrypted, err := eg.Decrypt(keys.PrivateKey, ciphertext, MaxBits16)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, decrypted, "Should have the same value")

	decrypted, err = eg.Decrypt(keys.PrivateKey, ciphertext, MaxBits32)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, decrypted, "Should have the same value")

	// Using a different private key to decrypt should yield an error.
	decryptedWrongly, err := eg.Decrypt(altKeys.PrivateKey, ciphertext, MaxBits32)
	require.Zero(t, decryptedWrongly)
	require.Error(t, err, "Should be unable to decrypt using the wrong private key")

	// Test overflow behavior
	ciphertextOverflow, _, err := eg.Encrypt(keys.PublicKey, math.MaxUint64)
	require.Nil(t, err, "Should have no error while encrypting")
	decryptedOverflow, err := eg.Decrypt(keys.PrivateKey, ciphertextOverflow, MaxBits32)
	require.Zero(t, decryptedOverflow)
	require.Error(t, err, "Should be unable to decrypt the invalid overflow value")
}

// Due to the size of 48 bit numbers, this test takes a really long time (~1hr) to run.
func Test48BitEncryptionDecryption(t *testing.T) {
	privateKey, err := GenerateKey()
	require.Nil(t, err)

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	// First decrypt a 32 bit number (sets up the decryptor for a later test)
	value := uint64(108092)
	ciphertext, _, err := eg.Encrypt(keys.PublicKey, value)
	require.Nil(t, err, "Should have no error while encrypting")

	decrypted, err := eg.DecryptLargeNumber(keys.PrivateKey, ciphertext, MaxBits48)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, value, decrypted, "Should have the same value")

	// Create a large <48 bit number to be encrypted.
	largeValue := uint64(1 << 39)
	largeCiphertext, _, err := eg.Encrypt(keys.PublicKey, largeValue)
	require.Nil(t, err, "Should have no error while encrypting")

	largeDecrypted, err := eg.DecryptLargeNumber(keys.PrivateKey, largeCiphertext, MaxBits48)
	require.Nil(t, err, "Should have no error while decrypting")
	require.Equal(t, largeValue, largeDecrypted, "Should have the same value")

	// Attempting to decrypt with the wrong max bits set should yield an error.
	decryptedWrongly, err := eg.DecryptLargeNumber(keys.PrivateKey, largeCiphertext, MaxBits32)
	require.Zero(t, decryptedWrongly)
	require.Error(t, err, "Should be unable to decrypt using the wrong maxBits")

	// Decrypting the 48 bit value should not corrupt the map for 32 bit values.
	decrypted, err = eg.DecryptLargeNumber(keys.PrivateKey, ciphertext, MaxBits32)
	require.Nil(t, err, "Should still have no error while decrypting")
	require.Equal(t, value, decrypted, "Should still have the same value")

	// Passing in an invalid maxBits should yield an error.
	_, err = eg.DecryptLargeNumber(keys.PrivateKey, largeCiphertext, MaxBits(64))
	require.Error(t, err, "Should be unable to decrypt using an invalid maxBits")
	require.Equal(t, "maxBits must be at most 48, provided (64)", err.Error())
}

func TestAddCiphertext(t *testing.T) {
	privateKey, _ := GenerateKey()
	altPrivateKey, _ := GenerateKey()

	ed25519 := curves.ED25519()
	eg := NewTwistedElgamal(ed25519)

	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)
	altKeys, _ := eg.KeyGen(*altPrivateKey, DefaultTestDenom)

	// Happy Path
	value1 := uint64(30842)
	ciphertext1, _, err := eg.Encrypt(keys.PublicKey, value1)
	require.Nil(t, err, "Should have no error while encrypting")

	value2 := uint64(1901)
	ciphertext2, _, err := eg.Encrypt(keys.PublicKey, uint64(value2))
	require.Nil(t, err, "Should have no error while encrypting")

	ciphertextSum, err := AddCiphertext(ciphertext1, ciphertext2)
	require.Nil(t, err, "Should have no error while adding ciphertexts")

	decrypted, err := eg.Decrypt(keys.PrivateKey, ciphertextSum, MaxBits32)
	require.Nil(t, err, "Should have no error while decrypting")
	require.NotNil(t, decrypted)
	require.Equal(t, value1+value2, decrypted, "Decrypted sum should be correct")

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

	_, err = eg.Decrypt(keys.PrivateKey, ciphertextSum, MaxBits32)
	require.Error(t, err, "Ciphertext should be undecodable using either private key")

	_, err = eg.Decrypt(altKeys.PrivateKey, ciphertextSum, MaxBits32)
	require.Error(t, err, "Ciphertext should be undecodable using either private key")
}

func TestTwistedElGamal_InvalidCiphertext(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	invalidCt := &Ciphertext{}

	decrypted, err := eg.Decrypt(keys.PrivateKey, invalidCt, MaxBits48)
	require.Error(t, err, "Decryption should fail for invalid ciphertext")
	require.Equal(t, "invalid ciphertext", err.Error())
	require.Zero(t, decrypted, "Decrypted value should be zero for invalid ciphertext")
}

func TestTwistedElGamal_NilPrivateKey(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Generate a valid key pair for comparison
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	// Encrypt a value with a valid public key
	value := uint64(12345)
	ciphertext, _, err := eg.Encrypt(keys.PublicKey, value)
	require.Nil(t, err, "Encryption should not fail with a valid public key")

	// Attempt to decrypt with a nil private key
	decrypted, err := eg.Decrypt(nil, ciphertext, MaxBits32)
	require.Error(t, err, "Decryption should fail with a nil private key")
	require.Equal(t, "invalid private key", err.Error())
	require.Zero(t, decrypted, "Decrypted value should be zero with a nil private key")
}

func TestTwistedElGamal_EncryptDecryptWithRand(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Generate a valid key pair for comparison
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	message := uint64(555555555)
	randomFactor := curve.Scalar.Random(rand.Reader)
	ct, _, err := eg.EncryptWithRand(keys.PublicKey, message, randomFactor)
	require.NoError(t, err, "Encryption with randomFactor should not fail")

	decrypted, err := eg.DecryptLargeNumber(keys.PrivateKey, ct, MaxBits48)
	require.NoError(t, err, "Decryption should not fail")
	require.Equal(t, message, decrypted, "Decrypted message should match original")
}

func TestTwistedElGamal_DecryptWithZeroBits(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Generate a valid key pair for comparison
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	message := uint64(555555555)
	randomFactor := curve.Scalar.Random(rand.Reader)
	ct, _, err := eg.EncryptWithRand(keys.PublicKey, message, randomFactor)
	require.NoError(t, err, "Encryption with randomFactor should not fail")

	_, err = eg.DecryptLargeNumber(keys.PrivateKey, ct, MaxBits(0))
	require.Error(t, err, "Decryption should fail")
	require.Equal(t, "failed to find value", err.Error())
}

func TestTwistedElGamal_EncryptInvalidKey(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Test with nil public key
	_, _, err := eg.Encrypt(nil, 12345)
	require.Error(t, err, "Encryption should fail with a nil public key")
	require.Equal(t, "invalid public key", err.Error())
}

func TestTwistedElGamal_EncryptInvalidRandomFactor(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Generate a valid key pair for comparison
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	// Test with nil public key
	_, _, err := eg.EncryptWithRand(keys.PublicKey, uint64(12345), nil)
	require.Error(t, err, "Encryption should fail with nil random factor")
	require.Equal(t, "invalid random factor", err.Error())
}

func TestTwistedElGamal_EncryptBoundaryValues(t *testing.T) {
	curve := curves.ED25519()
	eg := NewTwistedElgamal(curve)

	// Generate a valid key pair for comparison
	privateKey, _ := GenerateKey()
	keys, _ := eg.KeyGen(*privateKey, DefaultTestDenom)

	// Test with the smallest possible value (0)
	_, _, err := eg.Encrypt(keys.PublicKey, 0)
	require.NoError(t, err, "Encryption should not fail with the smallest possible value")

	// Test with the largest possible value (MaxUint64)
	_, _, err = eg.Encrypt(keys.PublicKey, math.MaxUint64)
	require.NoError(t, err, "Encryption should not fail with the largest possible value")
}
