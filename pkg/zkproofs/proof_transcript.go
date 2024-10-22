package zkproofs

import (
	"crypto/sha512"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// ProofTranscript represents a transcript of messages used in a zero-knowledge proof
type ProofTranscript struct {
	messages [][]byte
}

// NewProofTranscript creates a new proof transcript
func NewProofTranscript() *ProofTranscript {
	return &ProofTranscript{messages: make([][]byte, 0)}
}

// AppendMessage appends a message to the transcript
func (t *ProofTranscript) AppendMessage(label string, data []byte) {
	t.messages = append(t.messages, append([]byte(label), data...))
}

// ChallengeScalar generates a challenge scalar from the transcript
func (t *ProofTranscript) ChallengeScalar() curves.Scalar {
	hasher := sha512.New()
	for _, msg := range t.messages {
		hasher.Write(msg)
	}
	var sum [64]byte
	copy(sum[:], hasher.Sum(nil))

	s, err := curves.ED25519().Scalar.SetBytesWide(sum[:])
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	return s
}
