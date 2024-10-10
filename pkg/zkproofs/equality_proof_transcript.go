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

func (t *EqualityProofTranscript) AppendMessage(label string, data []byte) {
	t.messages = append(t.messages, append([]byte(label), data...))
}

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
