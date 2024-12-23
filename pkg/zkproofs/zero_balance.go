package zkproofs

import (
	"encoding/json"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

// ZeroBalanceProof represents a zero-knowledge proof that a ciphertext encrypts 0 number.
type ZeroBalanceProof struct {
	Yp curves.Point
	Yd curves.Point
	Z  curves.Scalar
}

// NewZeroBalanceProof generates a zero-knowledge proof that a ciphertext encrypts 0 number.
// Parameters:
// - keypair: The Twisted El Gamal Keypair used to generate the given ciphertext
// - ciphertext: The Ciphertext which we want to prove encrypts a value of 0
func NewZeroBalanceProof(
	keypair *elgamal.KeyPair,
	ciphertext *elgamal.Ciphertext,
) (*ZeroBalanceProof, error) {
	if keypair == nil || keypair.PublicKey == nil || keypair.PrivateKey == nil {
		return nil, errors.New("keypair is invalid")
	}

	if ciphertext == nil || ciphertext.D == nil || ciphertext.C == nil {
		return nil, errors.New("ciphertext is invalid")
	}

	// Extract necessary values
	P := keypair.PublicKey
	s := keypair.PrivateKey
	D := ciphertext.D

	// Generate random masking factor y
	curve := curves.ED25519()
	y, err := GenerateRandomNonZeroScalar(curve)
	if err != nil {
		return nil, err
	}

	// Compute Yp = y * P and Yd = y * D
	Yp := P.Mul(y)
	Yd := D.Mul(y)

	// Append commitments to the transcript
	transcript := NewProofTranscript()
	transcript.AppendMessage("Yp", Yp.ToAffineCompressed())
	transcript.AppendMessage("Yd", Yd.ToAffineCompressed())

	// Generate the challenge scalar from the transcript
	c := transcript.ChallengeScalar()

	// Compute Z = c * s + y
	Z := c.Mul(s).Add(y)

	return &ZeroBalanceProof{
		Yp: Yp,
		Yd: Yd,
		Z:  Z,
	}, nil
}

// VerifyZeroBalance verifies the that ciphertext encrypts 0 number.
// Parameters:
// - proof: The ZeroBalanceProof to verify
// - pubKey: The public key used to encrypt the ciphertext
// - ciphertext: The ciphertext to verify
func VerifyZeroBalance(
	proof *ZeroBalanceProof,
	pubKey *curves.Point,
	ciphertext *elgamal.Ciphertext,
) bool {
	if proof == nil || pubKey == nil || ciphertext == nil || ciphertext.C == nil || ciphertext.D == nil {
		return false
	}
	if !proof.validateContents() {
		return false
	}

	// Extract necessary values
	P := *pubKey
	C := ciphertext.C
	D := ciphertext.D

	eg := elgamal.NewTwistedElgamal()
	H := eg.GetH()

	// Append commitments to the transcript
	transcript := NewProofTranscript()
	transcript.AppendMessage("Yp", proof.Yp.ToAffineCompressed())
	transcript.AppendMessage("Yd", proof.Yd.ToAffineCompressed())

	// Generate the challenge scalar from the transcript
	c := transcript.ChallengeScalar()

	// VerifyCipherCipherEquality z * P == c * H + Yp
	lhsYp := P.Mul(proof.Z)   // z * P
	cH := H.Mul(c)            // c * H
	rhsYp := cH.Add(proof.Yp) // c * H + Yp

	if !lhsYp.Equal(rhsYp) {
		return false
	}

	// VerifyCipherCipherEquality z * D == c * C + Yd
	lhsYd := D.Mul(proof.Z)   // z * D
	cC := C.Mul(c)            // c * C
	rhsYd := cC.Add(proof.Yd) // c * C + Yd

	return lhsYd.Equal(rhsYd)
}

func (p *ZeroBalanceProof) validateContents() bool {
	if p.Yp == nil || p.Yd == nil || p.Z == nil {
		return false
	}

	// We leave out p.Yd since it is valid for Yd to be zero (Ciphertext.D can be Identity point)
	if p.Yp.IsIdentity() || p.Z.IsZero() {
		return false
	}

	return true
}

// MarshalJSON for ZeroBalanceProof
func (p *ZeroBalanceProof) MarshalJSON() ([]byte, error) {
	// Serialize the points and scalars to a format you prefer
	return json.Marshal(map[string]interface{}{
		"yp": p.Yp.ToAffineCompressed(),
		"yd": p.Yd.ToAffineCompressed(),
		"z":  p.Z.Bytes(),
	})
}

// UnmarshalJSON for ZeroBalanceProof
func (p *ZeroBalanceProof) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		Yp []byte `json:"yp"`
		Yd []byte `json:"yd"`
		Z  []byte `json:"z"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ed25519 := curves.ED25519()
	// Convert the byte arrays back into curve points and scalars
	yp, err := ed25519.Point.FromAffineCompressed(temp.Yp)
	if err != nil {
		return err
	}
	yd, err := ed25519.Point.FromAffineCompressed(temp.Yd)
	if err != nil {
		return err
	}
	z, err := ed25519.Scalar.SetBytes(temp.Z)
	if err != nil {
		return err
	}

	// Assign the decoded values to the ZeroBalanceProof struct
	p.Yp = yp
	p.Yd = yd
	p.Z = z

	return nil
}
