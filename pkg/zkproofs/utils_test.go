package zkproofs

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Basic test for getting a non-zero scalar.
func TestGenerateRandomNonZeroScalar(t *testing.T) {
	scalar, err := GenerateRandomNonZeroScalar(curves.ED25519())

	// The function throws an err if zero is generated after 5 tries.
	// There should be a virtually 0 chance of this happening. It's most likely due to a randomness issue.
	if err != nil {
		t.Errorf("Failed to generate zero. This is improbable and probably an error")
	}
	if scalar.IsZero() {
		t.Errorf("Expected non-zero scalar, got zero")
	}
}
