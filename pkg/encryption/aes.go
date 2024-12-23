package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// GetAESKey derives a 32-byte AES key using the provided bytes.
// It employs HKDF with SHA-256, using the private key bytes.
// No additional salt is added here so ensure that the privateBytes are already salted or hashed.
func GetAESKey(privateBytes []byte) ([]byte, error) {
	if len(privateBytes) == 0 {
		return nil, fmt.Errorf("bytes is empty")
	}

	// Create an HKDF reader using SHA-256
	hkdf := hkdf.New(sha256.New, privateBytes, nil, []byte("aes key derivation"))

	// Allocate a 32-byte array for the AES key
	aesKey := make([]byte, 32)

	_, err := io.ReadFull(hkdf, aesKey[:])
	if err != nil {
		return nil, err
	}

	return aesKey, nil
}

// EncryptAESGCM encrypts a big.Int value using AES-GCM with a 32-byte key.
// Key must be a len 32 byte array for AES-256
func EncryptAESGCM(value *big.Int, key []byte) (string, error) {
	// Validate the key length
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}

	// Create a GCM cipher mode instance
	aesgcm, err := getCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Serialize the big.Int value as a big-endian byte array
	valueBytes := value.Bytes()

	// Encrypt the data
	ciphertext := aesgcm.Seal(nonce, nonce, valueBytes, nil)

	// Encode to Base64 for storage or transmission
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCM Key must be a len 32 byte array for AES-256
func DecryptAESGCM(ciphertextBase64 string, key []byte) (*big.Int, error) {
	// Decode the Base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher mode instance
	aesgcm, err := getCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the nonce
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Convert the plaintext (byte array) to a big.Int
	value := new(big.Int).SetBytes(plaintext)

	return value, nil
}

// getCipher Creates the cipher from the key. Key must be a len 32 byte array for AES-256
func getCipher(key []byte) (cipher.AEAD, error) {
	// Create a new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher mode instance
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}
