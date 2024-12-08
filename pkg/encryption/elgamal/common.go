package elgamal

import (
	"crypto/sha256"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"golang.org/x/crypto/hkdf"
)

// H_STRING H is a random point on the elliptic curve that is unrelated to G.
const H_STRING = "gPt25pi0eDphSiXWu0BIeIvyVATCtwhslTqfqvNhW2c"

// KeyGen generates a new key pair for the Twisted ElGamal encryption scheme.
// The private key is derived from the provided privateBytes and denom string. Ensure that the privateBytes passed is not exposed.
func (teg TwistedElGamal) KeyGen(privateBytes []byte) (*KeyPair, error) {
	// Fixed base point H
	H := teg.GetH()

	s, err := teg.getPrivateKeyFromBytes(privateBytes)
	if err != nil {
		return nil, err
	}

	// Compute the public key P = s^(-1) * H
	sInv, _ := s.Invert()

	P := H.Mul(sInv) // P = s^(-1) * H

	return &KeyPair{
		PublicKey:  P,
		PrivateKey: s,
	}, nil
}

// GetG returns the generator point G for the TwistedElGamal instance.
// This is derived from the underlying elliptic curve's generator point.
func (teg TwistedElGamal) GetG() curves.Point {
	return curves.Point.Generator(teg.curve.Point)
}

// GetH returns the hashed point H for the TwistedElGamal instance.
// The hash is computed using a predefined string constant H_STRING.
// This point is used as part of the ElGamal encryption scheme.
func (teg TwistedElGamal) GetH() curves.Point {
	bytes := []byte(H_STRING)
	return teg.curve.Point.Hash(bytes)
}

func (teg TwistedElGamal) getPrivateKeyFromBytes(privateBytes []byte) (curves.Scalar, error) {
	// Hash the denom to get a salt.
	salt := sha256.Sum256([]byte("elgamal scalar derivation salt"))

	// Create an HKDF reader using SHA-256
	hkdf := hkdf.New(sha256.New, privateBytes, salt[:], []byte("elgamal scalar derivation"))

	// Generate 64 bytes of randomness from HKDF output
	var scalarBytes [64]byte
	_, err := io.ReadFull(hkdf, scalarBytes[:])
	if err != nil {
		return nil, err
	}

	// Initialize the scalar (private key) using the generated bytes
	s, err := teg.curve.Scalar.SetBytesWide(scalarBytes[:])
	if err != nil {
		return nil, err
	}

	return s, nil
}
