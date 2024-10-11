package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/bulletproof"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/gtank/merlin"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

const rangeDomain = "rangeDomain"
const ippDomain = "ippDomain"

type RangeProof struct {
	Proof      *bulletproof.RangeProof
	Randomness curves.Point
	UpperBound int
}

// NewRangeProof a range proof for some ciphertext that proves the value is between 0 and 2^upperBound
// Note that while this proof generator takes in the plaintext of the value, it will only work in conjunction with a
// ciphertext that encrypts value using the given randomness.
func NewRangeProof(upperBound, value int, randomness curves.Scalar) (*RangeProof, error) {
	curve := curves.ED25519()
	prover, err := bulletproof.NewRangeProver(upperBound, getRangeDomain(), getIppDomain(), *curve)
	if err != nil {
		return nil, err
	}

	eg := elgamal.NewTwistedElgamal()
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)
	transcript := getTranscript()

	vScalar := curve.Scalar.New(value)
	proof, err := prover.Prove(vScalar, randomness, upperBound, g, h, u, transcript)
	if err != nil {
		return nil, err
	}
	return &RangeProof{
		Proof:      proof,
		Randomness: u,
		UpperBound: upperBound,
	}, nil
}

// VerifyRangeProof verifies the range proof for the given ciphertext
func VerifyRangeProof(proof *RangeProof, ciphertext elgamal.Ciphertext) (bool, error) {
	curve := curves.ED25519()
	// Verifier gets the proof, the commitment, the generators to verify the value is within the range
	verifier, err := bulletproof.NewRangeVerifier(proof.UpperBound, getRangeDomain(), getIppDomain(), *curve)
	if err != nil {
		return false, err
	}

	eg := elgamal.NewTwistedElgamal()
	g := eg.GetG()
	h := eg.GetH()

	verified, err := verifier.Verify(proof.Proof, ciphertext.C, g, h, proof.Randomness, proof.UpperBound, getTranscript())
	if err != nil {
		return false, err
	}

	return verified, nil
}

func getRangeDomain() []byte {
	return []byte(rangeDomain)
}

func getIppDomain() []byte {
	return []byte(ippDomain)
}

func getTranscript() *merlin.Transcript {
	return merlin.NewTranscript("proof")
}

// MarshalJSON for RangeProof
func (r *RangeProof) MarshalJSON() ([]byte, error) {
	// Use the MarshalBinary method to convert the bulletproof RangeProof to a byte array
	binaryProof := r.Proof.MarshalBinary()

	// Serialize the entire struct, including the binary proof
	return json.Marshal(map[string]interface{}{
		"proof":       binaryProof,
		"randomness":  r.Randomness.ToAffineCompressed(), // Serialize randomness as a point
		"upper_bound": r.UpperBound,                      // Serialize the upper bound as is
	})
}

// UnmarshalJSON for RangeProof
func (r *RangeProof) UnmarshalJSON(data []byte) error {
	// Temporary structure to hold the incoming JSON
	var temp struct {
		Proof      []byte `json:"proof"`
		Randomness []byte `json:"randomness"`
		UpperBound int    `json:"upper_bound"`
	}

	// Unmarshal the JSON into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519 := curves.ED25519()

	// Initialize the RangeProof with the appropriate curve using NewRangeProof
	r.Proof = bulletproof.NewRangeProof(ed25519) // Using the correct curve

	// Unmarshal the proof using the UnmarshalBinary method, which will populate all fields
	if err := r.Proof.UnmarshalBinary(temp.Proof); err != nil {
		return err
	}

	// Unmarshal the randomness field
	randomness, err := ed25519.Point.FromAffineCompressed(temp.Randomness)
	if err != nil {
		return err
	}
	r.Randomness = randomness

	// Set the upper bound
	r.UpperBound = temp.UpperBound

	return nil
}