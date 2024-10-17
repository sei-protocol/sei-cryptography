package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"math/big"
)

// CiphertextValidityProof represents a zero-knowledge proof that a ciphertext is valid.
type CiphertextValidityProof struct {
	Commitment1 curves.Point
	Commitment2 curves.Point
	Response1   curves.Scalar
	Response2   curves.Scalar
}

// NewCiphertextValidityProof generates a zero-knowledge proof that the given ciphertext is properly encrypted using the given Public Key.
// Parameters:
// - pedersenOpening: The randomness factor used in the encrypting the Ciphertext.
// - pubKey: The public key used in the encryption.
// - ciphertext: The ciphertext to prove the validity of.
// - message: The message that was encrypted in the ciphertext.
func NewCiphertextValidityProof(pedersenOpening *curves.Scalar, pubKey curves.Point, ciphertext *elgamal.Ciphertext, message uint64) (*CiphertextValidityProof, error) {
	// Validate input
	if pedersenOpening == nil {
		return nil, errors.New("invalid randomness factor")
	}

	if pubKey == nil {
		return nil, errors.New("invalid public key")
	}

	if ciphertext == nil || ciphertext.C == nil || ciphertext.D == nil {
		return nil, errors.New("invalid ciphertext")
	}

	eg := elgamal.NewTwistedElgamal()

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
	// The challenge is basically just a hash of all the provided values. This locks in the values and makes sure that
	// the proof cannot be for some other set of values.
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("C1", Commitment1.ToAffineCompressed())
	transcript.AppendMessage("C2", Commitment2.ToAffineCompressed())
	challenge := transcript.ChallengeScalar()

	// Step 4: Generate responses
	Response1 := challenge.MulAdd(*pedersenOpening, rBlind) // Response1 = rBlind + challenge * pedersenOpening
	Response2 := challenge.MulAdd(x, xBlind)                // Response2 = xBlind + challenge * x

	return &CiphertextValidityProof{
		Commitment1: Commitment1,
		Commitment2: Commitment2,
		Response1:   Response1,
		Response2:   Response2,
	}, nil
}

// VerifyCiphertextValidity verifies the zero-knowledge proof that a ciphertext is valid.
// Parameters:
// - proof: The proof to verify.
// - pubKey: The public key used in the encryption.
// - ciphertext: The ciphertext to prove the validity of.
func VerifyCiphertextValidity(proof *CiphertextValidityProof, pubKey curves.Point, ciphertext *elgamal.Ciphertext) bool {
	// Validate input
	if proof == nil || proof.Commitment1 == nil || proof.Commitment2 == nil || proof.Response1 == nil ||
		proof.Response2 == nil || pubKey == nil || ciphertext == nil || ciphertext.C == nil || ciphertext.D == nil {
		return false
	}

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()
	G := eg.GetG()

	// Step 0: Recompute the challenge using the Fiat-Shamir heuristic.
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("C1", proof.Commitment1.ToAffineCompressed())
	transcript.AppendMessage("C2", proof.Commitment2.ToAffineCompressed())
	challenge := transcript.ChallengeScalar()

	// Step 1: Recompute Commitment1
	response1H := H.Mul(proof.Response1)      // response1 * H
	response2G := G.Mul(proof.Response2)      // response2 * G
	challengeC := ciphertext.C.Mul(challenge) // challenge * C
	recomputedCommitment1 := response1H.Add(response2G).Sub(challengeC)

	// Step 2: Recompute Commitment2
	challengeD := ciphertext.D.Mul(challenge) // challenge * D
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
	p.Response1 = response1
	p.Response2 = response2

	return nil
}
