package zkproofs

import (
	"encoding/json"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

// CiphertextCiphertextEqualityProof represents a zero-knowledge proof that two ciphertexts are encrypting the same
// value.
type CiphertextCiphertextEqualityProof struct {
	Y0 curves.Point
	Y1 curves.Point
	Y2 curves.Point
	Y3 curves.Point
	Zs curves.Scalar
	Zx curves.Scalar
	Zr curves.Scalar
}

// NewCiphertextCiphertextEqualityProof generates a new ciphertext-ciphertext proof.
// This proof demonstrates that two ciphertexts are encrypting the same value.
//
// Parameters:
// - sourceKeypair: The ElGamal keypair associated with the first ciphertext to be proved.
// - destinationPubKey: The ElGamal public key associated with the second ElGamal ciphertext.
// - sourceCiphertext: The first ElGamal ciphertext for which the prover knows a decryption key.
// - destinationOpening: The opening (randomness) associated with the second ElGamal ciphertext.
// - amount: The message associated with the ElGamal ciphertext and Pedersen commitment.
func NewCiphertextCiphertextEqualityProof(
	sourceKeypair *elgamal.KeyPair,
	destinationPubKey *curves.Point,
	sourceCiphertext *elgamal.Ciphertext,
	destinationOpening *curves.Scalar,
	amount *curves.Scalar,
) (*CiphertextCiphertextEqualityProof, error) {
	// validate input
	if sourceKeypair == nil || sourceKeypair.PublicKey == nil || sourceKeypair.PrivateKey == nil {
		return nil, errors.New("keypair is invalid")
	}

	if destinationPubKey == nil {
		return nil, errors.New("destinationPubKey is invalid")
	}

	if sourceCiphertext == nil || sourceCiphertext.C == nil || sourceCiphertext.D == nil {
		return nil, errors.New("sourceCiphertext is invalid")
	}

	if destinationOpening == nil {
		return nil, errors.New("destinationOpening is invalid")
	}

	if amount == nil {
		return nil, errors.New("amount is invalid")
	}

	// Extract necessary values
	pSource := sourceKeypair.PublicKey
	dSource := sourceCiphertext.D
	pDestination := *destinationPubKey

	s := sourceKeypair.PrivateKey
	x := *amount
	r := *destinationOpening

	// Generate random scalars
	curve := curves.ED25519()
	ys, err := GenerateRandomNonZeroScalar(curve)
	if err != nil {
		return nil, err
	}
	yx, err := GenerateRandomNonZeroScalar(curve)
	if err != nil {
		return nil, err
	}
	yr, err := GenerateRandomNonZeroScalar(curve)
	if err != nil {
		return nil, err
	}

	eg := elgamal.NewTwistedElgamal()
	G := eg.GetG()
	H := eg.GetH()

	// Compute Y0, Y1, Y2, Y3
	// Compute Y0 = ys * pSource
	Y0 := pSource.Mul(ys)

	// Compute Y1 = yx * G + ys * dSource
	yxG := G.Mul(yx)
	ysD := dSource.Mul(ys)
	Y1 := yxG.Add(ysD)

	// Compute Y2 = yx * G + yr * H
	yrH := H.Mul(yr)
	Y2 := yxG.Add(yrH)

	// Compute Y3 = yr * pDestination
	Y3 := pDestination.Mul(yr)

	// Append to transcript
	transcript := NewProofTranscript()
	transcript.AppendMessage("Y0", Y0.ToAffineCompressed())
	transcript.AppendMessage("Y1", Y1.ToAffineCompressed())
	transcript.AppendMessage("Y2", Y2.ToAffineCompressed())
	transcript.AppendMessage("Y3", Y3.ToAffineCompressed())

	// Generate challenge scalar
	c := transcript.ChallengeScalar()

	// Compute masked values
	Zs := ys.Add(c.Mul(s))
	Zx := yx.Add(c.Mul(x))
	Zr := yr.Add(c.Mul(r))

	// Return proof
	return &CiphertextCiphertextEqualityProof{
		Y0: Y0,
		Y1: Y1,
		Y2: Y2,
		Y3: Y3,
		Zs: Zs,
		Zx: Zx,
		Zr: Zr,
	}, nil
}

// VerifyCiphertextCiphertextEquality Function to verify the cipher-cipher proof
// Parameters:
// - proof: The proof to be verified.
// - sourcePubKey: The ElGamal public key associated with the first ElGamal ciphertext.
// - destinationPubKey: The ElGamal public key associated with the second ElGamal ciphertext.
// - sourceCiphertext: The first ElGamal ciphertext to be compared.
// - destinationCiphertext: The second ElGamal ciphertext to be compared.
func VerifyCiphertextCiphertextEquality(
	proof *CiphertextCiphertextEqualityProof,
	sourcePubKey *curves.Point,
	destinationPubKey *curves.Point,
	sourceCiphertext *elgamal.Ciphertext,
	destinationCiphertext *elgamal.Ciphertext,
) bool {
	// validate inputs
	if proof == nil || sourcePubKey == nil || destinationPubKey == nil ||
		sourceCiphertext == nil || sourceCiphertext.C == nil || sourceCiphertext.D == nil ||
		destinationCiphertext == nil || destinationCiphertext.C == nil || destinationCiphertext.D == nil {
		return false
	}

	// validate proof for nil and zero values
	if !proof.validateContents() {
		return false
	}

	// Extract necessary values
	pSource := *sourcePubKey
	cSource := sourceCiphertext.C
	dSource := sourceCiphertext.D

	pDestination := *destinationPubKey
	cDestination := destinationCiphertext.C
	dDestination := destinationCiphertext.D

	// Recreate the transcript
	transcript := NewProofTranscript()
	// Append Y0, Y1, Y2, Y3 to transcript
	transcript.AppendMessage("Y0", proof.Y0.ToAffineCompressed())
	transcript.AppendMessage("Y1", proof.Y1.ToAffineCompressed())
	transcript.AppendMessage("Y2", proof.Y2.ToAffineCompressed())
	transcript.AppendMessage("Y3", proof.Y3.ToAffineCompressed())

	// Generate challenge scalar
	c := transcript.ChallengeScalar()

	eg := elgamal.NewTwistedElgamal()

	// Extract G and H base points
	G := eg.GetG()
	H := eg.GetH()

	// Check Y0: zs * P_source == c * H + Y0
	lhsY0 := pSource.Mul(proof.Zs)
	cH := H.Mul(c)
	rhsY0 := proof.Y0.Add(cH)

	if !lhsY0.Equal(rhsY0) {
		return false
	}

	// Check zx * G + zs * D_source == c * C_source + Y1
	zxG := G.Mul(proof.Zx)
	zsD := dSource.Mul(proof.Zs)
	lhsY1 := zxG.Add(zsD)

	cC := cSource.Mul(c)
	rhsY1 := proof.Y1.Add(cC)

	if !lhsY1.Equal(rhsY1) {
		return false
	}

	// Check Y2: zx * G + zr * H == c * C_destination + Y2
	zrH := H.Mul(proof.Zr)
	lhsY2 := zxG.Add(zrH)

	cCd := cDestination.Mul(c)
	rhsY2 := proof.Y2.Add(cCd)

	if !lhsY2.Equal(rhsY2) {
		return false
	}

	// Check Y3: zr * P_destination == c * D_destination + Y3
	lhsY3 := pDestination.Mul(proof.Zr)
	cDd := dDestination.Mul(c)

	rhsY3 := proof.Y3.Add(cDd)

	return lhsY3.Equal(rhsY3)
}

func (c *CiphertextCiphertextEqualityProof) validateContents() bool {
	// Validate that fields are not nil
	if c == nil || c.Y0 == nil || c.Y1 == nil || c.Y2 == nil || c.Y3 == nil || c.Zs == nil ||
		c.Zx == nil || c.Zr == nil {
		return false
	}

	// Validate that fields are non zero. Though it is technically possible if the randomly generated scalars are zero, it is highly unlikely (1 in 2^255 chance)
	if c.Y0.IsIdentity() || c.Y1.IsIdentity() || c.Y2.IsIdentity() || c.Y3.IsIdentity() || c.Zr.IsZero() || c.Zs.IsZero() || c.Zx.IsZero() {
		return false
	}

	return true
}

// MarshalJSON for CiphertextCiphertextEqualityProof
func (p *CiphertextCiphertextEqualityProof) MarshalJSON() ([]byte, error) {
	// Serialize the points and scalars to a format you prefer
	return json.Marshal(map[string]interface{}{
		"y0": p.Y0.ToAffineCompressed(), // Assuming ToAffineCompressed returns a byte slice
		"y1": p.Y1.ToAffineCompressed(), // Serialize Point to compressed bytes
		"y2": p.Y2.ToAffineCompressed(), // Serialize Point to compressed bytes
		"y3": p.Y3.ToAffineCompressed(), // Serialize Point to compressed bytes
		"zs": p.Zs.Bytes(),              // Serialize Scalar to bytes
		"zx": p.Zx.Bytes(),              // Serialize Scalar to bytes
		"zr": p.Zr.Bytes(),              // Serialize Scalar to bytes
	})
}

// UnmarshalJSON for CiphertextCiphertextEqualityProof
func (p *CiphertextCiphertextEqualityProof) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		Y0 []byte `json:"y0"`
		Y1 []byte `json:"y1"`
		Y2 []byte `json:"y2"`
		Y3 []byte `json:"y3"`
		Zs []byte `json:"zs"`
		Zx []byte `json:"zx"`
		Zr []byte `json:"zr"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519Curve := curves.ED25519()
	// Convert the byte arrays back into curve points and scalars
	y0, err := ed25519Curve.Point.FromAffineCompressed(temp.Y0)
	if err != nil {
		return err
	}
	y1, err := ed25519Curve.Point.FromAffineCompressed(temp.Y1)
	if err != nil {
		return err
	}
	y2, err := ed25519Curve.Point.FromAffineCompressed(temp.Y2)
	if err != nil {
		return err
	}
	y3, err := ed25519Curve.Point.FromAffineCompressed(temp.Y3)
	if err != nil {
		return err
	}
	zs, err := ed25519Curve.Scalar.SetBytes(temp.Zs)
	if err != nil {
		return err
	}
	zx, err := ed25519Curve.Scalar.SetBytes(temp.Zx)
	if err != nil {
		return err
	}
	zr, err := ed25519Curve.Scalar.SetBytes(temp.Zr)
	if err != nil {
		return err
	}

	// Assign the decoded values to the CiphertextCiphertextEqualityProof struct
	p.Y0 = y0
	p.Y1 = y1
	p.Y2 = y2
	p.Y3 = y3
	p.Zs = zs
	p.Zx = zx
	p.Zr = zr

	return nil
}
