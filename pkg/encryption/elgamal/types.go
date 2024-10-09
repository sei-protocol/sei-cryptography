package elgamal

import (
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// KeyPair represents a public-private key pair.
type KeyPair struct {
	PublicKey  curves.Point
	PrivateKey curves.Scalar
}

// Ciphertext represents the ciphertext of a message.
type Ciphertext struct {
	C curves.Point `json:"c,omitempty"`
	D curves.Point `json:"d,omitempty"`
}

// Custom type for maxBits
type MaxBits uint

// Define allowed values for maxBits using the custom type
const (
	MaxBits16 MaxBits = 16
	MaxBits32 MaxBits = 32
	MaxBits40 MaxBits = 40
	MaxBits48 MaxBits = 48
)

// MarshalJSON for Ciphertext
func (c *Ciphertext) MarshalJSON() ([]byte, error) {
	// Serialize the points to a format you prefer
	return json.Marshal(map[string]interface{}{
		"c": c.C.ToAffineCompressed(), // Assuming `ToAffineCompressed` returns a byte slice
		"d": c.D.ToAffineCompressed(),
	})
}

// UnmarshalJSON for Ciphertext
func (c *Ciphertext) UnmarshalJSON(data []byte) error {
	// Create a temporary structure to decode JSON
	var temp struct {
		C []byte `json:"c"`
		D []byte `json:"d"`
	}

	// Unmarshal into the temp structure
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Convert the byte arrays back into curve points
	// Assuming `FromCompressed` is a method to parse compressed points
	ed25519Curve := curves.ED25519()
	pointC, err := ed25519Curve.Point.FromAffineCompressed(temp.C)
	if err != nil {
		return err
	}
	pointD, err := ed25519Curve.Point.FromAffineCompressed(temp.D)
	if err != nil {
		return err
	}

	// Assign the points to the Ciphertext struct
	c.C = pointC
	c.D = pointD

	return nil
}
