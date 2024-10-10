package zkproofs

import (
	"crypto/sha512"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type EqualityProofTranscript struct {
	messages [][]byte
}

func NewEqualityProofTranscript() *EqualityProofTranscript {
	return &EqualityProofTranscript{messages: make([][]byte, 0)}
}

// AppendMessage appends a message to the transcript
func (t *EqualityProofTranscript) AppendMessage(label string, data []byte) {
	t.messages = append(t.messages, append([]byte(label), data...))
}

// ChallengeScalar generates a challenge scalar from the transcript
func (t *EqualityProofTranscript) ChallengeScalar() curves.Scalar {
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
