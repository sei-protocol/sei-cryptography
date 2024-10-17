package zkproofs

import (
	"crypto/rand"
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

// NewPubKeyValidityProof generates the proof the creator of the given PublicKey also knows the associated PrivateKey,
// and that the PublicKey is thus valid.
// Parameters:
// - pubKey: The PublicKey to prove the validity of.
// - privKey: The PrivateKey associated with the PublicKey.
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
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("P", pubKey.ToAffineCompressed())
	transcript.AppendMessage("Y", Y.ToAffineCompressed())
	c := transcript.ChallengeScalar()

	// Compute sInv = s^{-1}
	sInv, _ := privKey.Invert()

	// Response z = c * sInv + y
	z := c.MulAdd(sInv, y) // z = c * sInv + y

	return &PubKeyValidityProof{
		Y: Y,
		Z: z,
	}, nil
}

// VerifyPubKeyValidity validates that the given PublicKey is a valid PublicKey under the Twisted El Gamal scheme,
// and that the prover knows the corresponding PrivateKey.
// Parameters:
// - pubKey: The PublicKey to validate.
// - proof: The proof that the prover knows the corresponding PrivateKey.
func VerifyPubKeyValidity(pubKey curves.Point, proof PubKeyValidityProof) bool {
	// Validate input
	if pubKey == nil || proof.Y == nil || proof.Z == nil {
		return false
	}

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()

	// Recompute the challenge c
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("P", pubKey.ToAffineCompressed())
	transcript.AppendMessage("Y", proof.Y.ToAffineCompressed())

	c := transcript.ChallengeScalar()

	// Compute lhs = z * H
	lhs := H.Mul(proof.Z) // lhs = z * H

	// Compute rhs = c * P + Y
	cP := pubKey.Mul(c)    // c * P
	rhs := cP.Add(proof.Y) // rhs = c * P + Y

	// Check if z * H == c * P + Y
	return lhs.Equal(rhs)
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
