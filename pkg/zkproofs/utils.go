package zkproofs

import (
	"crypto/rand"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Generates a non-zero random scalar. The chances of generating a zero scalar are very low.
func GenerateRandomScalar(curve *curves.Curve) (curves.Scalar, error) {
	attempts := 0
	scalar := curve.Scalar.Random(rand.Reader)
	// Try 5 times to generate a non zero scalar. The chance that this fails with a normal random number generator is impossibly low.
	for scalar.IsZero() && attempts < 5 {
		curve.Scalar.Random(rand.Reader)
		attempts += 1
	}

	if scalar.IsZero() {
		return nil, errors.New("failed to generate a non-zero scalar")
	}

	return scalar, nil
}
