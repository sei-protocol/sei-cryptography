package zkproofs

import (
	"crypto/sha512"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEqualityProofTranscript_AppendMessage(t *testing.T) {
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("label1", []byte("data1"))
	transcript.AppendMessage("label2", []byte("data2"))

	assert.Equal(t, 2, len(transcript.messages), "Number of messages should be 2")
	assert.Equal(t, "label1data1", string(transcript.messages[0]), "First message should match")
	assert.Equal(t, "label2data2", string(transcript.messages[1]), "Second message should match")
}

func TestEqualityProofTranscript_ChallengeScalar(t *testing.T) {
	transcript := NewEqualityProofTranscript()
	transcript.AppendMessage("label1", []byte("data1"))
	transcript.AppendMessage("label2", []byte("data2"))

	scalar := transcript.ChallengeScalar()
	hasher := sha512.New()
	hasher.Write([]byte("label1data1"))
	hasher.Write([]byte("label2data2"))
	var sum [64]byte
	copy(sum[:], hasher.Sum(nil))
	expectedScalar, _ := curves.ED25519().Scalar.SetBytesWide(sum[:])

	assert.Equal(t, expectedScalar, scalar, "Challenge scalar should match expected value")
}

func TestEqualityProofTranscript_EmptyMessages(t *testing.T) {
	transcript := NewEqualityProofTranscript()
	scalar := transcript.ChallengeScalar()

	hasher := sha512.New()
	var sum [64]byte
	copy(sum[:], hasher.Sum(nil))
	expectedScalar, _ := curves.ED25519().Scalar.SetBytesWide(sum[:])

	assert.Equal(t, expectedScalar, scalar, "Challenge scalar should match expected value for empty messages")
}
