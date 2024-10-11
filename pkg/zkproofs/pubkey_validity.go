package zkproofs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

// PubKeyValidityProof The Public Key Validation goes as follows:
// For some keypair s (privKey) and s_inv*H (pubKey)
// 1. Generate some random scalar y
// 2. We agree on some random challenge c, which is the hash of the commitment y.
// 3. The prover constructs the proof z = c*s_inv + y. which masks s_inv
// 4. The verifier checks that z*H = c*Pubkey + y*H. This expands to c*s_inv*H + y*H = c*(s_inv*H) + y*H
type PubKeyValidityProof struct {
	Y curves.Point
	Z curves.Scalar
}

// NewPubKeyValidityProof generates the sigma protocol proof
// The proof here is that the creator of this PubKey also knows the corresponding PrivateKey
func NewPubKeyValidityProof(pubKey curves.Point, privKey curves.Scalar) (*PubKeyValidityProof, error) {
	// Validate input
	if pubKey == nil {
		return nil, errors.New("invalid public key")
	}

	if privKey == nil {
		return nil, errors.New("invalid private key")
	}

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()
	// Prover generates a random scalar y
	y := curves.ED25519().Scalar.Random(rand.Reader)

	// Commitment Y = y * H
	Y := H.Mul(y)

	// Generate challenge c based on P and Y
	c := generateChallenge(pubKey, Y)

	// Compute sInv = s^{-1}
	sInv, _ := privKey.Invert()

	// Response z = c * sInv + y
	z := c.MulAdd(sInv, y) // z = c * sInv + y

	return &PubKeyValidityProof{
		Y: Y,
		Z: z,
	}, nil
}

// VerifyPubKeyValidityProof verifies the validity of the proof
func VerifyPubKeyValidityProof(pubKey curves.Point, proof PubKeyValidityProof) bool {
	// Validate input
	if pubKey == nil || proof.Y == nil || proof.Z == nil {
		return false
	}

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()
	// Recompute the challenge c
	c := generateChallenge(pubKey, proof.Y)

	// Compute lhs = z * H
	lhs := H.Mul(proof.Z) // lhs = z * H

	// Compute rhs = c * P + Y
	cP := pubKey.Mul(c)    // c * P
	rhs := cP.Add(proof.Y) // rhs = c * P + Y

	// Check if z * H == c * P + Y
	return lhs.Equal(rhs)
}

// generateChallenge generates a challenge c by hashing P and Y
func generateChallenge(P, Y curves.Point) curves.Scalar {
	// Hash P and Y using SHA-256
	hash := sha256.New()

	hash.Write(P.ToAffineCompressed())
	hash.Write(Y.ToAffineCompressed())
	digest := hash.Sum(nil)

	// Convert hash output into a scalar
	return curves.ED25519().Scalar.Hash(digest)
}

// MarshalJSON for PubKeyValidityProof
func (p *PubKeyValidityProof) MarshalJSON() ([]byte, error) {
	// Serialize the points and scalars to a format you prefer
	return json.Marshal(map[string]interface{}{
		"y": p.Y.ToAffineCompressed(),
		"z": p.Z.Bytes(),
	})
}

// UnmarshalJSON for PubKeyValidityProof
func (p *PubKeyValidityProof) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		Y []byte `json:"y"`
		Z []byte `json:"z"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519 := curves.ED25519()
	// Convert the byte arrays back into curve points and scalars
	y, err := ed25519.Point.FromAffineCompressed(temp.Y)
	if err != nil {
		return err
	}
	z, err := ed25519.Scalar.SetBytes(temp.Z)
	if err != nil {
		return err
	}

	// Assign the decoded values to the PubKeyValidityProof struct
	p.Y = y
	p.Z = z

	return nil
}
