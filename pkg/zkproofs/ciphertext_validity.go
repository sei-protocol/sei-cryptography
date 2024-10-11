package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"math/big"
)

// CiphertextValidityProof represents a zero-knowledge proof that a ciphertext is valid.
type CiphertextValidityProof struct {
	Commitment1 curves.Point
	Commitment2 curves.Point
	Challenge   curves.Scalar
	Response1   curves.Scalar
	Response2   curves.Scalar
}

// NewCiphertextValidityProof generates a zero-knowledge proof that a ciphertext is properly encrypted.
func NewCiphertextValidityProof(message uint64, r *curves.Scalar, pubKey curves.Point, ct *elgamal.Ciphertext) *CiphertextValidityProof {
	eg := elgamal.NewTwistedElgamal()

	var proof CiphertextValidityProof
	H := eg.GetH()
	G := eg.GetG()

	ed25519 := curves.ED25519()
	// Convert message to a scalar
	messageValue := new(big.Int).SetUint64(message)
	x, _ := ed25519.Scalar.SetBigInt(messageValue)

	// Step 1: Generate random blinding factors for the proof
	rBlind := ed25519.Scalar.Random(crand.Reader) // Blinding factor for random value r
	xBlind := ed25519.Scalar.Random(crand.Reader) // Blinding factor for random value x

	// Step 2: Create commitments
	rBlindH := H.Mul(rBlind)            // rBlind * H
	xBlindG := G.Mul(xBlind)            // xBlind * G
	Commitment1 := rBlindH.Add(xBlindG) // Commitment1 = rBlind * H + xBlind * G

	Commitment2 := pubKey.Mul(rBlind) // Commitment2 = rBlind * P

	// Step 3: Generate a challenge using the Fiat-Shamir heuristic.
	// The challenge is basically just a hash of all the provided values. This locks in the values and makes sure that the proof cannot be for some other set of values.
	hashData := append(Commitment1.ToAffineCompressed(), Commitment2.ToAffineCompressed()...)
	hashData = append(hashData, ct.C.ToAffineCompressed()...)
	hashData = append(hashData, ct.D.ToAffineCompressed()...)
	challenge := ed25519.Scalar.Hash(hashData)

	// Step 4: Generate responses
	Response1 := challenge.MulAdd(*r, rBlind) // Response1 = rBlind + challenge * r
	Response2 := challenge.MulAdd(x, xBlind)  // Response2 = xBlind + challenge * x

	// Store the proof
	proof.Commitment1 = Commitment1
	proof.Commitment2 = Commitment2
	proof.Challenge = challenge
	proof.Response1 = Response1
	proof.Response2 = Response2

	return &proof
}

// VerifyCiphertextValidityProof verifies the zero-knowledge proof that a ciphertext is valid.
func VerifyCiphertextValidityProof(proof *CiphertextValidityProof, pubKey curves.Point, ct *elgamal.Ciphertext) bool {

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()
	G := eg.GetG()

	// Step 1: Recompute Commitment1
	response1H := H.Mul(proof.Response1)    // response1 * H
	response2G := G.Mul(proof.Response2)    // response2 * G
	challengeC := ct.C.Mul(proof.Challenge) // challenge * C
	recomputedCommitment1 := response1H.Add(response2G).Sub(challengeC)

	// Step 2: Recompute Commitment2
	challengeD := ct.D.Mul(proof.Challenge) // challenge * D
	recomputedCommitment2 := pubKey.Mul(proof.Response1).Sub(challengeD)

	// Step 3: Check if the recomputed commitments match the original commitments
	return recomputedCommitment1.Equal(proof.Commitment1) && recomputedCommitment2.Equal(proof.Commitment2)
}

// MarshalJSON for CiphertextValidityProof
func (p *CiphertextValidityProof) MarshalJSON() ([]byte, error) {
	// Serialize the points and scalars to a format you prefer
	return json.Marshal(map[string]interface{}{
		"commitment1": p.Commitment1.ToAffineCompressed(), // Assuming ToAffineCompressed returns a byte slice
		"commitment2": p.Commitment2.ToAffineCompressed(),
		"challenge":   p.Challenge.Bytes(), // Serialize Scalar to bytes
		"response1":   p.Response1.Bytes(), // Serialize Scalar to bytes
		"response2":   p.Response2.Bytes(), // Serialize Scalar to bytes
	})
}

// UnmarshalJSON for CiphertextValidityProof
func (p *CiphertextValidityProof) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		Commitment1 []byte `json:"commitment1"`
		Commitment2 []byte `json:"commitment2"`
		Challenge   []byte `json:"challenge"`
		Response1   []byte `json:"response1"`
		Response2   []byte `json:"response2"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519 := curves.ED25519()
	// Convert the byte arrays back into curve points and scalars
	commitment1, err := ed25519.Point.FromAffineCompressed(temp.Commitment1)
	if err != nil {
		return err
	}
	commitment2, err := ed25519.Point.FromAffineCompressed(temp.Commitment2)
	if err != nil {
		return err
	}
	challenge, err := ed25519.Scalar.SetBytes(temp.Challenge)
	if err != nil {
		return err
	}
	response1, err := ed25519.Scalar.SetBytes(temp.Response1)
	if err != nil {
		return err
	}
	response2, err := ed25519.Scalar.SetBytes(temp.Response2)
	if err != nil {
		return err
	}

	// Assign the decoded values to the CiphertextValidityProof struct
	p.Commitment1 = commitment1
	p.Commitment2 = commitment2
	p.Challenge = challenge
	p.Response1 = response1
	p.Response2 = response2

	return nil
}
