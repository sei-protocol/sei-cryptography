package zkproofs

import (
	"crypto/rand"
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func GenerateRandomScalar(curve *curves.Curve) (curves.Scalar, error) {
	attempts := 0
	scalar := curve.Scalar.Random(rand.Reader)
	for scalar.IsZero() && attempts < 5 {
		curve.Scalar.Random(rand.Reader)
		attempts += 1
	}

	if scalar.IsZero() {
		return nil, errors.New("failed to generate a non-zero scalar")
	}

	return scalar, nil
}
