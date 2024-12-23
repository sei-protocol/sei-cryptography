package zkproofs

import (
	crand "crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/bulletproof"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/gtank/merlin"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	testutils "github.com/sei-protocol/sei-cryptography/pkg/testing"
	"github.com/stretchr/testify/require"
)

type TestVerifier struct {
	actualVerifier VerifierFactory
	counter        int
}

func (t *TestVerifier) getVerifier(upperBound int) (*bulletproof.RangeVerifier, error) {
	t.counter++
	return t.actualVerifier.getVerifier(upperBound)
}

// Coinbase Kryptology's bulletproof package is used to generate range proofs
func TestValueIsInRange(t *testing.T) {
	curve := curves.ED25519()
	value := big.NewInt(100)
	v, _ := curve.Scalar.SetBigInt(value)
	n := 64 // the range is [0, 2^64]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)

	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, u)
	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	// Verifier gets the proof, the commitment, the generators to verify the value is within the range
	verifier, err := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)

	transcriptVerifier := merlin.NewTranscript("test")
	verified, err := verifier.Verify(proof, ciphertext.C, proofGenerators, n, transcriptVerifier)
	require.NoError(t, err)
	require.True(t, verified)

	ciphertext101, _, err := eg.Encrypt(keyPair.PublicKey, big.NewInt(101))
	require.Nil(t, err)
	verified, err = verifier.Verify(proof, ciphertext101.C, proofGenerators, n, transcriptVerifier)
	require.Error(t, err)
	require.False(t, verified)
}

func TestRangeAttacksAreInfeasible(t *testing.T) {
	curve := curves.ED25519()
	value := big.NewInt(100)
	v, _ := curve.Scalar.SetBigInt(value)
	n := 64 // the range is [0, 2^64]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	g := eg.GetG()
	h := eg.GetH()
	u := curve.Point.Random(crand.Reader)
	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, u)
	transcript := merlin.NewTranscript("test")

	proof, err := prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.NoError(t, err)

	// for 90 to 110 generate ciphertexts and see if we can guess the encrypted value
	for i := 90; i < 110; i++ {
		transcriptVerifier := merlin.NewTranscript("test")
		ct, _, e := eg.Encrypt(keyPair.PublicKey, big.NewInt(int64(i)))
		require.NoError(t, e)

		verifier, e := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
		require.NoError(t, e)

		verified, _ := verifier.Verify(proof, ct.C, proofGenerators, n, transcriptVerifier)
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
		verified, _ := verifier.Verify(proof, ciphertext.C, proofGenerators, i, transcriptVerifier)
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
	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, u)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(v, gamma, n, proofGenerators, transcript)
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
	proofGenerators := bulletproof.NewRangeProofGenerators(g, h, u)
	transcript := merlin.NewTranscript("test")
	_, err = prover.Prove(v, gamma, n, proofGenerators, transcript)
	require.Error(t, err)
}

func TestRangeProofs(t *testing.T) {
	value := big.NewInt(100)
	n := 64 // the range is [0, 2^64]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	ed25519factory := Ed25519RangeVerifierFactory{}
	verifierFactory := NewCachedRangeVerifierFactory(&ed25519factory)
	verified, err := VerifyRangeProof(proof, ciphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)

	// Check that a ciphertext with a different value cannot use the same proof to verify as true, even if it meets the requirements.
	ciphertext101, _, err := eg.Encrypt(keyPair.PublicKey, big.NewInt(101))
	require.Nil(t, err)

	verified, err = VerifyRangeProof(proof, ciphertext101, n, verifierFactory)
	require.Error(t, err)
	require.False(t, verified)
}

func TestRangeProofsLargeN(t *testing.T) {
	value := big.NewInt(100)
	n := 128 // the range is [0, 2^128]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	ed25519factory := Ed25519RangeVerifierFactory{}
	verifierFactory := NewCachedRangeVerifierFactory(&ed25519factory)

	verified, err := VerifyRangeProof(proof, ciphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)

	// Check that a ciphertext with a different value cannot use the same proof to verify as true, even if it meets the requirements.
	ciphertext101, _, err := eg.Encrypt(keyPair.PublicKey, big.NewInt(101))
	require.Nil(t, err)

	verified, err = VerifyRangeProof(proof, ciphertext101, n, verifierFactory)
	require.Error(t, err)
	require.False(t, verified)
}

// We test marshaling and unmarshaling of the range proof this way as bulletproof.RangeProof does not implement Equals
// and particular fields are not exported.
func TestRangeProofsWithMarshaling(t *testing.T) {
	value := big.NewInt(100)
	n := 64 // the range is [0, 2^64]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	// Marshal the proof to JSON
	marshaledProof, err := json.Marshal(proof)
	require.NoError(t, err, "Marshaling should not produce an error")

	// Unmarshal the JSON back to a RangeProof
	var unmarshaled RangeProof
	err = json.Unmarshal(marshaledProof, &unmarshaled)
	require.NoError(t, err, "Unmarshaling should not produce an error")

	ed25519factory := Ed25519RangeVerifierFactory{}
	verifierFactory := NewCachedRangeVerifierFactory(&ed25519factory)

	verified, err := VerifyRangeProof(&unmarshaled, ciphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeProofs_InvalidInput(t *testing.T) {
	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	_, gamma, _ := eg.Encrypt(keyPair.PublicKey, big.NewInt(10))

	t.Run("Invalid upper bound", func(t *testing.T) {
		// Proof is nil
		_, err := NewRangeProof(
			0, big.NewInt(0), gamma,
		)
		require.EqualError(t, err, "range NewRangeProver: getGeneratorPoints splitPointVector: length of points must be at least one")
	})

	t.Run("Invalid randomness factor", func(t *testing.T) {
		// Proof is nil
		_, err := NewRangeProof(
			1, big.NewInt(0), nil,
		)
		require.EqualError(t, err, "invalid randomness factor")
	})
}

func TestVerifyRangeProof_InvalidInput(t *testing.T) {
	privateKey := testutils.GenerateKey()
	eg := elgamal.NewTwistedElgamal()
	value := big.NewInt(10)
	keyPair, _ := eg.KeyGen(*privateKey)
	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	proof, err := NewRangeProof(64, value, gamma)
	require.NoError(t, err)

	ed25519factory := Ed25519RangeVerifierFactory{}
	verifierFactory := NewCachedRangeVerifierFactory(&ed25519factory)

	t.Run("Nil proof", func(t *testing.T) {
		// Proof is nil
		valid, err := VerifyRangeProof(nil, ciphertext, 64, verifierFactory)
		require.EqualError(t, err, "invalid proof")
		require.False(t, valid)
	})

	t.Run("Proof with nil fields", func(t *testing.T) {
		valid, err := VerifyRangeProof(&RangeProof{}, ciphertext, 64, verifierFactory)
		require.EqualError(t, err, "invalid proof")
		require.False(t, valid)
	})

	t.Run("nil ciphertext", func(t *testing.T) {
		// Proof is nil
		valid, err := VerifyRangeProof(proof, nil, 64, verifierFactory)
		require.EqualError(t, err, "invalid ciphertext")
		require.False(t, valid)
	})

	t.Run("Ciphertext with nil fields", func(t *testing.T) {
		// Proof is nil
		valid, err := VerifyRangeProof(proof, &elgamal.Ciphertext{}, 64, verifierFactory)
		require.EqualError(t, err, "invalid ciphertext")
		require.False(t, valid)
	})
}

// Test that it is fine to reuse verifiers.
func TestRangeProofVerifierReuse(t *testing.T) {
	value := big.NewInt(10)
	n := 128 // the range is [0, 2^128]

	privateKey := testutils.GenerateKey()

	eg := elgamal.NewTwistedElgamal()
	keyPair, err := eg.KeyGen(*privateKey)
	require.Nil(t, err, "Error generating key pair")

	ciphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, value)

	proof, err := NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	// Create a verifier with len 128 vector
	ed25519factory := Ed25519RangeVerifierFactory{}
	verifierFactory := NewCachedRangeVerifierFactory(&ed25519factory)

	// Verify that this works normally for verifying a proof with the same upper bound
	verified, err := VerifyRangeProof(proof, ciphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)

	// Verify that this still works on a different proof
	proof, err = NewRangeProof(n, value, gamma)
	require.Nil(t, err)

	verified, err = VerifyRangeProof(proof, ciphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)

	// Verify that this still works on a proof on a different value
	newValue := big.NewInt(10238032)
	newCiphertext, gamma, _ := eg.Encrypt(keyPair.PublicKey, newValue)
	proof, err = NewRangeProof(n, newValue, gamma)
	require.Nil(t, err)

	verified, err = VerifyRangeProof(proof, newCiphertext, n, verifierFactory)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestRangeVerifierIsLazyLoadedFromCache(t *testing.T) {
	upperBound := 64
	curve := curves.ED25519()
	expectedVerifier, err := bulletproof.NewRangeVerifier(upperBound, getRangeDomain(), getIppDomain(), *curve)
	require.NoError(t, err)

	testVerifier := &TestVerifier{
		actualVerifier: &Ed25519RangeVerifierFactory{},
	}
	cachedVerifier := NewCachedRangeVerifierFactory(testVerifier)

	// First invocation should call the actual verifier
	actualVerifier, err := cachedVerifier.getVerifier(upperBound)
	require.NoError(t, err)
	require.Equal(t, expectedVerifier, actualVerifier)
	require.Equal(t, 1, testVerifier.counter)

	// Second invocation should return the cached verifier, so the counter should not increment
	actualVerifier, err = cachedVerifier.getVerifier(upperBound)
	require.NoError(t, err)
	require.Equal(t, expectedVerifier, actualVerifier)
	require.Equal(t, 1, testVerifier.counter)
}
