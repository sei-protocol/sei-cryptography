package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"golang.org/x/crypto/hkdf"
)

// GenerateKey generates a new ECDSA private key using the secp256k1 curve.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

// GetAESKey derives a 32-byte AES key using the provided ECDSA private key and denomination string.
// It employs HKDF with SHA-256, using the ECDSA private key bytes and a SHA-256 hash of the denom as salt.
func GetAESKey(privKey ecdsa.PrivateKey, denom string) ([]byte, error) {
	if privKey.D == nil {
		return nil, fmt.Errorf("private key D is nil")
	}
	if len(denom) == 0 {
		return nil, fmt.Errorf("denom is empty")
	}
	// Convert the ECDSA private key to bytes
	privKeyBytes := privKey.D.Bytes()

	// Use a SHA-256 hash of the denom string as the salt
	salt := sha256.Sum256([]byte(denom))

	// Create an HKDF reader using SHA-256
	hkdf := hkdf.New(sha256.New, privKeyBytes, salt[:], []byte("aes key derivation"))

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
