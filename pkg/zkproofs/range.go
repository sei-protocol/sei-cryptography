package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"math/big"

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

type VerifierFactory interface {
	getVerifier(upperBound int) (*bulletproof.RangeVerifier, error)
}

// Caches the verifiers created for each upper bound
type CachedRangeVerifierFactory struct {
	verifiers map[int]*bulletproof.RangeVerifier
	delegator VerifierFactory
}

type Ed25519RangeVerifierFactory struct{}

func NewCachedRangeVerifierFactory(delegator VerifierFactory) *CachedRangeVerifierFactory {
	mapping := make(map[int]*bulletproof.RangeVerifier)

	return &CachedRangeVerifierFactory{
		verifiers: mapping,
		delegator: delegator,
	}
}

// NewRangeProof generates a range proof for some ciphertext that proves the value is between 0 and 2^upperBound
// Parameters:
// - upperBound The upper bound of the range we want to prove the value lies within, calculated as 2^upperBound
// - value: The value encrypted by the ciphertext on which we are creating this proof for
// - randomness: The randomness used in the generation of the ciphertext on which we are creating this proof for
func NewRangeProof(upperBound int, value *big.Int, randomness curves.Scalar) (*RangeProof, error) {
	if randomness == nil {
		return nil, errors.New("invalid randomness factor")
	}
	curve := curves.ED25519()
	prover, err := bulletproof.NewRangeProver(upperBound, getRangeDomain(), getIppDomain(), *curve)
	if err != nil {
		return nil, err
	}

	eg := elgamal.NewTwistedElgamal()
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)
	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, u)
	transcript := getTranscript()

	vScalar, err := curve.Scalar.SetBigInt(value)
	if err != nil {
		return nil, err
	}

	proof, err := prover.Prove(vScalar, randomness, upperBound, proofGenerators, transcript)
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
// Parameters:
// - proof: The range proof to verify
// - ciphertext: The ciphertext for which we are verifying the range proof
// - upperBound: The upper bound of the range we want to prove the value lies within, calculated as 2^upperBound
func VerifyRangeProof(proof *RangeProof, ciphertext *elgamal.Ciphertext, upperBound int, verifierFactory VerifierFactory) (bool, error) {
	// Validate input
	if proof == nil || proof.Proof == nil || proof.Randomness == nil {
		return false, errors.New("invalid proof")
	}

	if ciphertext == nil || ciphertext.C == nil || ciphertext.D == nil {
		return false, errors.New("invalid ciphertext")
	}

	eg := elgamal.NewTwistedElgamal()
	g := eg.GetG()
	h := eg.GetH()
	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, proof.Randomness)

	// Get the verifier from the cache, then verify.
	verifier, err := verifierFactory.getVerifier(upperBound)
	if err != nil {
		return false, err
	}
	verified, err := verifier.Verify(proof.Proof, ciphertext.C, proofGenerators, upperBound, getTranscript())
	if err != nil {
		return false, err
	}

	return verified, nil
}

func (c *CachedRangeVerifierFactory) getVerifier(upperBound int) (*bulletproof.RangeVerifier, error) {
	verifier, exists := c.verifiers[upperBound]
	if exists {
		return verifier, nil
	}

	verifier, err := c.delegator.getVerifier(upperBound)
	if err != nil {
		return nil, err
	}

	c.verifiers[upperBound] = verifier
	return verifier, nil
}

func (e *Ed25519RangeVerifierFactory) getVerifier(upperBound int) (*bulletproof.RangeVerifier, error) {
	curve := curves.ED25519()
	verifier, err := bulletproof.NewRangeVerifier(upperBound, getRangeDomain(), getIppDomain(), *curve)
	if err != nil {
		return nil, err
	}
	return verifier, nil
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
