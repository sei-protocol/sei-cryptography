package encryption

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetAESKey(t *testing.T) {
	tests := []struct {
		name         string
		privateKey   *ecdsa.PrivateKey
		denom        string
		expectEqual  bool
		anotherKey   *ecdsa.PrivateKey
		anotherDenom string
	}{
		{
			name:        "Deterministic Key Generation",
			privateKey:  generateTestKey(t),
			denom:       "factory/sei1239081236470/testToken",
			expectEqual: true,
		},
		{
			name:         "Different Denom (Salt) Generates Different Key",
			privateKey:   generateTestKey(t),
			denom:        "factory/sei1239081236470/testToken",
			anotherDenom: "factory/sei1239081236470/testToken1",
			expectEqual:  false,
		},
		{
			name:         "Different Denom (Salt) of same length Generates Different Key",
			privateKey:   generateTestKey(t),
			denom:        "factory/sei1239081236470/testToken1",
			anotherDenom: "factory/sei1239081236470/testToken2",
			expectEqual:  false,
		},
		{
			name:        "Different PrivateKey Generates Different Key",
			privateKey:  generateTestKey(t),
			denom:       "factory/sei1239081236470/testTokenN",
			anotherKey:  generateTestKey(t),
			expectEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesPK, err := GetAESKey(*tt.privateKey, tt.denom)
			require.Nil(t, err, "Should not have error here")

			if tt.anotherKey != nil {
				aesPKDiff, err := GetAESKey(*tt.anotherKey, tt.denom)
				require.Nil(t, err)
				require.NotEqual(t, aesPK, aesPKDiff, "PK should be different for different private keys")
			} else if tt.anotherDenom != "" {
				aesPKDiff, err := GetAESKey(*tt.privateKey, tt.anotherDenom)
				require.Nil(t, err)
				require.NotEqual(t, aesPK, aesPKDiff, "PK should be different for different salts")
			} else {

				aesPKAgain, err := GetAESKey(*tt.privateKey, tt.denom)
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
	_, err := GetAESKey(*new(ecdsa.PrivateKey), "valid/denom")
	require.Error(t, err, "Should return error for nil private key")

	invalidPrivateKey := &ecdsa.PrivateKey{ /* Invalid key data */ }
	_, err = GetAESKey(*invalidPrivateKey, "valid/denom")
	require.Error(t, err, "Should return error for invalid private key")

	validPrivateKey := generateTestKey(t)
	_, err = GetAESKey(*validPrivateKey, "")
	require.Error(t, err, "Should not allow empty denom(salt)")
}

func TestAESEncryptionDecryption(t *testing.T) {
	tests := []struct {
		name           string
		key            []byte
		anotherKey     []byte
		value          uint64
		expectError    bool
		decryptWithKey []byte
		encryptAgain   bool
	}{
		{
			name:        "Successful Encryption and Decryption",
			key:         []byte("examplekey12345678901234567890ab"), // 32 bytes for AES-256
			value:       3023,
			expectError: false,
		},
		{
			name:         "Encryption Yields Different Ciphertext If Encrypted Again",
			key:          []byte("examplekey12345678901234567890ab"),
			value:        3023,
			encryptAgain: true,
			expectError:  false,
		},
		{
			name:        "Different Key Produces Different Ciphertext",
			key:         []byte("examplekey12345678901234567890ab"),
			anotherKey:  []byte("randomkey12345678901234567890abc"), // 32 bytes for AES-256
			value:       3023,
			expectError: false,
		},
		{
			name:           "Decryption with Wrong Key",
			key:            []byte("examplekey12345678901234567890ab"),
			value:          3023,
			expectError:    true,
			decryptWithKey: []byte("wrongkey12345678901234567890ab"),
		},
		{
			name:        "Edge Case: Zero Value",
			key:         []byte("examplekey12345678901234567890ab"),
			value:       0,
			expectError: false,
		},
		{
			name:        "Edge Case: Maximum Uint64",
			key:         []byte("examplekey12345678901234567890ab"),
			value:       ^uint64(0),
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

	value := uint64(1234)

	for _, key := range invalidKeys {
		t.Run("InvalidKeyLength", func(t *testing.T) {
			_, err := EncryptAESGCM(value, key)
			require.Error(t, err, "Should return error for invalid key length")
		})
	}
}

func TestDecryptAESGCM_InvalidCiphertext(t *testing.T) {
	key := []byte("examplekey12345678901234567890ab")
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
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := GenerateKey()
	require.Nil(t, err, "Failed to generate private key")
	return privateKey
}
