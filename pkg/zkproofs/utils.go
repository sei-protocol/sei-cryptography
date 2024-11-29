package zkproofs

import (
	"crypto/rand"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// GenerateRandomNonZeroScalar Generates a non-zero random scalar.
// Parameters:
// - curve: The elliptic curve to use for scalar generation.
// Returns:
// - A non-zero random scalar.
// - An error if the scalar generation fails.
func GenerateRandomNonZeroScalar(curve *curves.Curve) (curves.Scalar, error) {
	var scalar curves.Scalar

	for attempts := 0; attempts < 5; attempts++ {
		scalar = curve.Scalar.Random(rand.Reader)
		if !scalar.IsZero() {
			return scalar, nil
		}
	}

	return nil, errors.New("failed to generate a non-zero scalar")
}
