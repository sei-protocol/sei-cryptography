package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/bulletproof"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/gtank/merlin"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/stretchr/testify/require"
	"testing"
)

// Coinbase Kryptology's bulletproof package is used to generate range proofs
func TestValueIsInRange(t *testing.T) {
	curve := curves.ED25519()
	value := 100
	v := curve.Scalar.New(value)
	n := 64 // the range is [0, 2^64]

	privateKey, err := elgamal.GenerateKey()
	require.Nil(t, err, "Error generating private key")

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey, TestDenom)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, err := eg.Encrypt(keyPair.PublicKey, uint64(value))

	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, g, h, u, transcript)
	require.NoError(t, err)

	// Verifier gets the proof, the commitment, the generators to verify the value is within the range
	verifier, err := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)

	transcriptVerifier := merlin.NewTranscript("test")
	verified, err := verifier.Verify(proof, ciphertext.C, g, h, u, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)

	ciphertext101, _, err := eg.Encrypt(keyPair.PublicKey, uint64(101))
	require.Nil(t, err)
	verified, err = verifier.Verify(proof, ciphertext101.C, g, h, u, n, transcriptVerifier)
	require.Error(t, err)
	require.False(t, verified)
}
func TestRangeAttacksAreInfeasible(t *testing.T) {
	curve := curves.ED25519()
	value := 100
	v := curve.Scalar.New(value)
	n := 64 // the range is [0, 2^64]

	privateKey, err := elgamal.GenerateKey()
	require.Nil(t, err, "Error generating private key")

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey, TestDenom)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, err := eg.Encrypt(keyPair.PublicKey, uint64(value))

	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, g, h, u, transcript)
	require.NoError(t, err)

	// for 90 to 110 generate ciphertexts and see if we can guess the encrypted value
	for i := 90; i < 110; i++ {
		transcriptVerifier := merlin.NewTranscript("test")
		ct, _, e := eg.Encrypt(keyPair.PublicKey, uint64(i))
		require.NoError(t, e)

		verifier, e := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
		require.NoError(t, e)

		verified, _ := verifier.Verify(proof, ct.C, g, h, u, n, transcriptVerifier)
		if verified {
			t.Errorf("Attack successful: the number is %d", i)
		}
	}

	// We know already that the value is in the range [0, 2^64]. For range  [2^2 to 2^63],
	// generate verifier for each range and see if we can narrow the range in which the value is.
	// Starting from 2^2 as bulletptoof panics for 2^0 and 2^1
	for i := 2; i < n; i++ {
		// Verifier gets the proof, the commitment, the generators to verify the value is within the range
		verifier, e := bulletproof.NewRangeVerifier(i, []byte("rangeDomain"), []byte("ippDomain"), *curve)
		require.NoError(t, e)

		transcriptVerifier := merlin.NewTranscript("test")

		require.NoError(t, e)
		verified, _ := verifier.Verify(proof, ciphertext.C, g, h, u, i, transcriptVerifier)
		if verified {
			t.Errorf("Attack successful: the number is in the range 2^%d", i)
		}
	}
}

func TestRangeVerifyNotInRange(t *testing.T) {
	curve := curves.ED25519()
	n := 2
	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.New(100)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(v, gamma, n, g, h, u, transcript)
	require.Error(t, err)
}

func TestRangeVerifyNotInRangeNegativeValue(t *testing.T) {
	curve := curves.ED25519()
	n := 64
	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	v := curve.Scalar.New(-100)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(v, gamma, n, g, h, u, transcript)
	require.Error(t, err)
}

func TestRangeProofs(t *testing.T) {
	value := 100
	n := 64 // the range is [0, 2^64]

	privateKey, err := elgamal.GenerateKey()
	require.Nil(t, err, "Error generating private key")

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey, TestDenom)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, err := eg.Encrypt(keyPair.PublicKey, uint64(value))

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	verified, err := VerifyRangeProof(proof, *ciphertext)
	require.NoError(t, err)
	require.True(t, verified)

	// Check that a ciphertext with a different value cannot use the same proof to verify as true, even if it meets the requirements.
	ciphertext101, _, err := eg.Encrypt(keyPair.PublicKey, uint64(101))
	require.Nil(t, err)

	verified, err = VerifyRangeProof(proof, *ciphertext101)
	require.Error(t, err)
	require.False(t, verified)
}

// We test marshaling and unmarshaling of the range proof this way as bulletproof.RangeProof does not implement Equals
// and particular fields are not exported.
func TestRangeProofsWithMarshaling(t *testing.T) {
	value := 100
	n := 64 // the range is [0, 2^64]

	privateKey, err := elgamal.GenerateKey()
	require.Nil(t, err, "Error generating private key")

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey, TestDenom)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, err := eg.Encrypt(keyPair.PublicKey, uint64(value))

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	// Marshal the proof to JSON
	marshaledProof, err := json.Marshal(proof)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a RangeProof
	var unmarshaled RangeProof
	err = json.Unmarshal(marshaledProof, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	verified, err := VerifyRangeProof(&unmarshaled, *ciphertext)
	require.NoError(t, err)
	require.True(t, verified)
}
