package zkproofs

import (
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

// CiphertextCommitmentEqualityProof represents a zero-knowledge proof that a ciphertext and a Pedersen commitment
// encode the same message.
type CiphertextCommitmentEqualityProof struct {
	Y0 curves.Point
	Y1 curves.Point
	Y2 curves.Point
	Zs curves.Scalar
	Zx curves.Scalar
	Zr curves.Scalar
}

// NewCiphertextCommitmentEqualityProof generates a new equality proof between a ciphertext and a Pedersen commitment.
// Parameters:
// - sourceKeypair: The ElGamal keypair associated with the ciphertext to be proved.
// - sourceCiphertext: The ElGamal ciphertext for which the prover knows a decryption key.
// - pedersenOpening: The opening (randomness) associated with the Pedersen commitment.
// - amount: The message associated with the ElGamal ciphertext and Pedersen commitment.
func NewCiphertextCommitmentEqualityProof(
	sourceKeypair *elgamal.KeyPair,
	sourceCiphertext *elgamal.Ciphertext,
	pedersenOpening *curves.Scalar,
	amount *curves.Scalar,
) (*CiphertextCommitmentEqualityProof, error) {
	// Validate input
	if sourceKeypair == nil || sourceKeypair.PublicKey == nil || sourceKeypair.PrivateKey == nil {
		return nil, errors.New("keypair is invalid")
	}

	if sourceCiphertext == nil || sourceCiphertext.D == nil || sourceCiphertext.C == nil {
		return nil, errors.New("sourceCiphertext is invalid")
	}

	if pedersenOpening == nil {
		return nil, errors.New("pedersenOpening is invalid")
	}

	if amount == nil {
		return nil, errors.New("amount is invalid")
	}

	// Extract necessary values
	P := sourceKeypair.PublicKey // Public key in twisted ElGamal aesgcm scheme
	D := sourceCiphertext.D      // D part of the twisted ElGamal ciphertext

	s := sourceKeypair.PrivateKey // Secret key in twisted ElGamal aesgcm scheme
	x := amount                   // Message in twisted ElGamal aesgcm scheme
	r := pedersenOpening          // Pedersen commitment
	eg := elgamal.NewTwistedElgamal()
	G := eg.GetG() // Fixed base point G
	H := eg.GetH() // Fixed base point H

	ed25519 := curves.ED25519()
	// Generate random masking factors
	ys := ed25519.Scalar.Random(rand.Reader)
	yx := ed25519.Scalar.Random(rand.Reader)
	yr := ed25519.Scalar.Random(rand.Reader)

	// Compute Y0 = ys * P
	Y0 := P.Mul(ys)

	// Compute Y1 = yx * G + ys * D
	yxG := G.Mul(yx)
	ysD := D.Mul(ys)
	Y1 := yxG.Add(ysD)

	// Compute Y2 = yx * G + yr * H
	yrH := H.Mul(yr)
	Y2 := yxG.Add(yrH)

	// Append commitments to the transcript
	transcript := NewProofTranscript()
	transcript.AppendMessage("Y0", Y0.ToAffineCompressed())
	transcript.AppendMessage("Y1", Y1.ToAffineCompressed())
	transcript.AppendMessage("Y2", Y2.ToAffineCompressed())

	// Generate the challenge scalar from the transcript
	c := transcript.ChallengeScalar()

	// Compute responses
	// zs = c * s + ys
	Zs := c.Mul(s).Add(ys)
	// zx = c * x + yx
	Zx := c.Mul(*x).Add(yx)
	// zr = c * r + yr
	Zr := c.Mul(*r).Add(yr)

	// Return the proof
	return &CiphertextCommitmentEqualityProof{
		Y0: Y0,
		Y1: Y1,
		Y2: Y2,
		Zs: Zs,
		Zx: Zx,
		Zr: Zr,
	}, nil
}

// VerifyCiphertextCommitmentEquality verifies the zero-knowledge equality proof between a ciphertext and a Pedersen
// commitment.
// Parameters:
// - proof: The proof to be verified.
// - sourcePubKey: The public key associated with the ciphertext to be proved.
// - sourceCiphertext: The ElGamal ciphertext for which the prover knows a decryption key.
// - pedersenCommitment: The Pedersen commitment to be proved.
func VerifyCiphertextCommitmentEquality(
	proof *CiphertextCommitmentEqualityProof,
	sourcePubKey *curves.Point,
	sourceCiphertext *elgamal.Ciphertext,
	pedersenCommitment *curves.Point,
) bool {
	// Validate input
	if proof == nil || sourcePubKey == nil || sourceCiphertext == nil || pedersenCommitment == nil {
		return false
	}

	// Validate proof
	if !proof.validateContents() {
		return false
	}

	// Extract necessary values
	P := *sourcePubKey
	D := sourceCiphertext.D
	cEg := sourceCiphertext.C
	cPed := *pedersenCommitment

	eg := elgamal.NewTwistedElgamal()
	G := eg.GetG()
	H := eg.GetH()

	// Append commitments to the transcript
	transcript := NewProofTranscript()
	transcript.AppendMessage("Y0", proof.Y0.ToAffineCompressed())
	transcript.AppendMessage("Y1", proof.Y1.ToAffineCompressed())
	transcript.AppendMessage("Y2", proof.Y2.ToAffineCompressed())

	// Generate the challenge scalar from the transcript
	c := transcript.ChallengeScalar()

	// VerifyCipherCipherEquality zs * P == c * H + Y0
	lhsY0 := P.Mul(proof.Zs) // zs * PEG
	cH := H.Mul(c)           // c * H
	rhsY0 := cH.Add(proof.Y0)
	if !lhsY0.Equal(rhsY0) {
		return false
	}

	// VerifyCipherCipherEquality zx * G + zs * D == c * cEg + Y1
	zxG := G.Mul(proof.Zx) // zx * G
	zsD := D.Mul(proof.Zs) // zs * D
	lhsY1 := zxG.Add(zsD)  // zx * G + zs * D
	cCeg := cEg.Mul(c)     // c * cEg
	rhsY1 := cCeg.Add(proof.Y1)
	if !lhsY1.Equal(rhsY1) {
		return false
	}

	// VerifyCipherCipherEquality zx * G + zr * H == c * cPed + Y2
	zxG2 := G.Mul(proof.Zx)      // zx * G
	zrH := H.Mul(proof.Zr)       // zr * H
	lhsY2 := zxG2.Add(zrH)       // zx * G + zr * H
	cCPed := cPed.Mul(c)         // c * cPed
	rhsY2 := cCPed.Add(proof.Y2) // c * cPed + Y2

	return lhsY2.Equal(rhsY2)
}

func (c *CiphertextCommitmentEqualityProof) validateContents() bool {
	if c.Y0 == nil || c.Y1 == nil || c.Y2 == nil || c.Zs == nil || c.Zx == nil || c.Zr == nil {
		return false
	}

	if c.Y0.IsIdentity() || c.Y1.IsIdentity() || c.Y2.IsIdentity() || c.Zs.IsZero() || c.Zx.IsZero() || c.Zr.IsZero() {
		return false
	}

	return true
}

// MarshalJSON for CiphertextCommitmentEqualityProof
func (p *CiphertextCommitmentEqualityProof) MarshalJSON() ([]byte, error) {
	// Serialize the points and scalars to a format you prefer
	return json.Marshal(map[string]interface{}{
		"y0": p.Y0.ToAffineCompressed(), // Assuming ToAffineCompressed returns a byte slice
		"y1": p.Y1.ToAffineCompressed(), // Serialize Point to compressed bytes
		"y2": p.Y2.ToAffineCompressed(), // Serialize Point to compressed bytes
		"zs": p.Zs.Bytes(),              // Serialize Scalar to bytes
		"zx": p.Zx.Bytes(),              // Serialize Scalar to bytes
		"zr": p.Zr.Bytes(),              // Serialize Scalar to bytes
	})
}

// UnmarshalJSON for CiphertextCommitmentEqualityProof
func (p *CiphertextCommitmentEqualityProof) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		Y0 []byte `json:"y0"`
		Y1 []byte `json:"y1"`
		Y2 []byte `json:"y2"`
		Zs []byte `json:"zs"`
		Zx []byte `json:"zx"`
		Zr []byte `json:"zr"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519 := curves.ED25519()
	// Convert the byte arrays back into curve points and scalars
	y0, err := ed25519.Point.FromAffineCompressed(temp.Y0)
	if err != nil {
		return err
	}
	y1, err := ed25519.Point.FromAffineCompressed(temp.Y1)
	if err != nil {
		return err
	}
	y2, err := ed25519.Point.FromAffineCompressed(temp.Y2)
	if err != nil {
		return err
	}
	zs, err := ed25519.Scalar.SetBytes(temp.Zs)
	if err != nil {
		return err
	}
	zx, err := ed25519.Scalar.SetBytes(temp.Zx)
	if err != nil {
		return err
	}
	zr, err := ed25519.Scalar.SetBytes(temp.Zr)
	if err != nil {
		return err
	}

	// Assign the decoded values to the CiphertextCommitmentEqualityProof struct
	p.Y0 = y0
	p.Y1 = y1
	p.Y2 = y2
	p.Zs = zs
	p.Zx = zx
	p.Zr = zr

	return nil
}
