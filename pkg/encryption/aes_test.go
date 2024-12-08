package encryption

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	TestDenom = "factory/sei1239081236470/testToken"
	TestKey   = "examplekey12345678901234567890ab"
)

func TestGetAESKey(t *testing.T) {
	tests := []struct {
		name         string
		privateKey   []byte
		denom        string
		expectEqual  bool
		anotherKey   []byte
		anotherDenom string
	}{
		{
			name:        "Deterministic Key Generation",
			privateKey:  generateTestKey(),
			expectEqual: true,
		},
		{
			name:        "Different PrivateKey Generates Different Key",
			privateKey:  generateTestKey(),
			anotherKey:  generateTestKey(),
			expectEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesPK, err := GetAESKey(tt.privateKey)
			require.Nil(t, err, "Should not have error here")

			if tt.anotherKey != nil {
				aesPKDiff, err := GetAESKey(tt.anotherKey)
				require.Nil(t, err)
				require.NotEqual(t, aesPK, aesPKDiff, "PK should be different for different private keys")
			} else {

				aesPKAgain, err := GetAESKey(tt.privateKey)
				require.Nil(t, err, "Should not have error here")
				if tt.expectEqual {
					require.Equal(t, aesPK, aesPKAgain, "PK should be deterministically generated")
				} else {
					require.NotEqual(t, aesPK, aesPKAgain, "PK should be different for different denoms")
				}
			}
		})
	}
}

func TestGetAESKey_InvalidInput(t *testing.T) {
	// Nil private key
	_, err := GetAESKey([]byte{})
	require.Error(t, err, "Should return error for nil private key")
}

func TestAESEncryptionDecryption(t *testing.T) {
	tests := []struct {
		name           string
		key            []byte
		anotherKey     []byte
		value          *big.Int
		expectError    bool
		decryptWithKey []byte
		encryptAgain   bool
	}{
		{
			name:        "Successful Encryption and Decryption",
			key:         []byte(TestKey), // 32 bytes for AES-256
			value:       big.NewInt(3023),
			expectError: false,
		},
		{
			name:         "Encryption Yields Different Ciphertext If Encrypted Again",
			key:          []byte(TestKey),
			value:        big.NewInt(3023),
			encryptAgain: true,
			expectError:  false,
		},
		{
			name:        "Different Key Produces Different Ciphertext",
			key:         []byte(TestKey),
			anotherKey:  []byte("randomkey12345678901234567890abc"), // 32 bytes for AES-256
			value:       big.NewInt(3023),
			expectError: false,
		},
		{
			name:           "Decryption with Wrong Key",
			key:            []byte(TestKey),
			value:          big.NewInt(3023),
			expectError:    true,
			decryptWithKey: []byte("wrongkey12345678901234567890ab"),
		},
		{
			name:        "Edge Case: Zero Value",
			key:         []byte(TestKey),
			value:       big.NewInt(0),
			expectError: false,
		},
		{
			name:        "Maximum Uint64",
			key:         []byte(TestKey),
			value:       new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1)), // 2^256 - 1
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptAESGCM(tt.value, tt.key)
			if tt.expectError && err != nil {
				// Expected error during encryption
				require.Error(t, err)
				return
			}
			require.Nil(t, err, "Should have no error encrypting")

			if tt.anotherKey != nil {
				encryptedAgain, err := EncryptAESGCM(tt.value, tt.anotherKey)
				require.Nil(t, err, "Should have no error encrypting with another key")
				require.NotEqual(t, encrypted, encryptedAgain, "Ciphertext should differ on encryption with different key")
			}

			if tt.decryptWithKey != nil {
				_, err := DecryptAESGCM(encrypted, tt.decryptWithKey)
				require.Error(t, err, "Should have an error decrypting with wrong key")
				return
			}

			decrypted, err := DecryptAESGCM(encrypted, tt.key)
			if tt.expectError {
				require.Empty(t, decrypted)
				require.Error(t, err, "Should have an error decrypting with wrong key")
			} else {
				require.Nil(t, err, "Should have no error decrypting")
				require.Equal(t, tt.value, decrypted)
			}

			// Additional checks for encryption consistency
			if tt.encryptAgain {
				encryptedAgain, err := EncryptAESGCM(tt.value, tt.key)
				require.Nil(t, err, "Should have no error encrypting again")
				require.NotEqual(t, encrypted, encryptedAgain, "Ciphertext should differ on re-encryption")
			}
		})
	}
}

func TestEncryptAESGCM_InvalidKeyLength(t *testing.T) {
	invalidKeys := [][]byte{
		{},                                     // Empty key
		[]byte("shortkey"),                     // Too short
		[]byte("thiskeyiswaytoolongforaesgcm"), // Too long
	}

	value := big.NewInt(1234)

	for _, key := range invalidKeys {
		t.Run("InvalidKeyLength", func(t *testing.T) {
			_, err := EncryptAESGCM(value, key)
			require.Error(t, err, "Should return error for invalid key length")
		})
	}
}

func TestDecryptAESGCM_InvalidCiphertext(t *testing.T) {
	key := []byte(TestKey)
	invalidCiphertexts := [][]byte{
		{}, // Empty ciphertext
		[]byte("invalidciphertext"),
	}

	for _, ct := range invalidCiphertexts {
		t.Run("InvalidCiphertext", func(t *testing.T) {
			decrypted, err := DecryptAESGCM(string(ct), key)
			require.Empty(t, decrypted)
			require.Error(t, err, "Should return error for invalid ciphertext")
		})
	}
}

// Helper function to generate a test private key
func generateTestKey() []byte {
	randomString := time.Now()
	return []byte(randomString.String())
}
