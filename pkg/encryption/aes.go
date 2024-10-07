package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

func GetAesKey(privKey ecdsa.PrivateKey, denom string) ([]byte, error) {
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
		return []byte{}, err
	}

	return aesKey, nil
}

// Key must be a len 32 byte array for AES-256
func EncryptAESGCM(value uint64, key []byte) (string, error) {
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

	plaintext := make([]byte, 8)
	// Convert the integer to []byte using BigEndian or LittleEndian
	binary.BigEndian.PutUint64(plaintext, value)

	// Encrypt the data
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	// Encode to Base64 for storage or transmission
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Key must be a len 32 byte array for AES-256
func DecryptAESGCM(ciphertextBase64 string, key []byte) (uint64, error) {
	// Decode the Base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return 0, err
	}

	// Create a GCM cipher mode instance
	aesgcm, err := getCipher(key)
	if err != nil {
		return 0, err
	}

	// Extract the nonce
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return 0, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	value := binary.BigEndian.Uint64(plaintext)

	return value, nil
}

// Creates the cipher from the key. Key must be a len 32 byte array for AES-256
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