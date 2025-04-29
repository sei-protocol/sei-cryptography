package elgamal

import (
	crand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/bwesterb/go-ristretto"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type TwistedElGamal struct {
	curve   *curves.Curve
	mapping map[string]uint64

	// Notes the sizes decrypted so far. This helps us know if the values we need are already in the map.
	maxMapping map[MaxBits]bool
}

// NewTwistedElgamal creates a new TwistedElGamal instance with ED25519 curve.
func NewTwistedElgamal() *TwistedElGamal {
	var s ristretto.Point
	s.SetZero()
	mapping := make(map[string]uint64)
	maxMapping := make(map[MaxBits]bool)
	mapping[s.String()] = 0

	return &TwistedElGamal{
		curve:      curves.ED25519(),
		maxMapping: maxMapping,
		mapping:    mapping,
	}
}

// Encrypt encrypts a message using the public key pk.
func (teg TwistedElGamal) Encrypt(pk curves.Point, message *big.Int) (*Ciphertext, curves.Scalar, error) {
	// Generate a random scalar r
	randomFactor := teg.curve.Scalar.Random(crand.Reader)

	return teg.encryptWithRand(pk, message, randomFactor)
}

// EncryptWithRand encrypts a message using the public key pk and a given random factor.
func (teg TwistedElGamal) encryptWithRand(pk curves.Point, message *big.Int, randomFactor curves.Scalar) (*Ciphertext, curves.Scalar, error) {
	if pk == nil {
		return nil, nil, fmt.Errorf("invalid public key")
	}

	if randomFactor == nil {
		return nil, nil, fmt.Errorf("invalid random factor")
	}

	// Fixed base points G and H
	H := teg.GetH()
	G := teg.GetG()

	// Convert message x (big.Int) to a scalar on the elliptic curve
	x, _ := teg.curve.Scalar.SetBigInt(message)

	// Compute the Pedersen commitment: C = r * H + x * G
	rH := H.Mul(randomFactor) // r * H
	xG := G.Mul(x)            // x * G
	C := rH.Add(xG)           // C = r * H + x * G

	// Compute the decryption handle: D = r * P
	D := pk.Mul(randomFactor) // D = r * P
	ciphertext := Ciphertext{
		C: C,
		D: D,
	}

	return &ciphertext, randomFactor, nil
}

// Decrypt decrypts the ciphertext ct using the private key sk = s. It can realistically only decrypt up to a maximum of a uint48.
// MaxBits denotes the maximum size of the decrypted message. The lower this can be set, the faster we can decrypt the message.
func (teg TwistedElGamal) Decrypt(sk curves.Scalar, ct *Ciphertext, maxBits MaxBits) (*big.Int, error) {
	if sk == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	if ct == nil || ct.C == nil || ct.D == nil {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	G := teg.GetG()

	// Compute s * D
	sD := ct.D.Mul(sk)

	// Compute C - s * D
	var result = ct.C.Sub(sD)

	// Now, we need to solve for x from x * G = result.
	// There's no direct method in go-ristretto for solving this, so in practice,
	// this step requires a brute force or precomputation to retrieve x.
	// For simplicity, let's assume we know the range of x and can brute force it.

	// We split x into x_lo and x_hi, the bottom and top 16 bits of x, such that x*G = (x_lo * G) + (x_hi * 2^(maxBits/2) * G)
	// First construct the mapping of x_hi * G * 2^(maxBits/2) : x_hi * 2^(maxBits/2) for all values of x_hi in the range of 2^(maxBits/2).
	if _, ok := teg.maxMapping[maxBits]; !ok {
		teg.updateIterMap(maxBits)
	}

	// Then iterate over all values of x_lo.
	// If for some value x_lo, (x * G) - (x_lo * G) exists in the map above, then we satisfy the equation above and x = x_lo + 2^(maxBits/2) * x_hi
	iMax := uint64(1<<(uint(maxBits)/2) - 1)

	for i := uint64(0); i < iMax; i++ {
		// Attempt to brute-force x.
		// We test all values of x_lo in (x * G) - x_lo * G
		xValue := new(big.Int).SetUint64(i)
		x, _ := teg.curve.Scalar.SetBigInt(xValue)

		xLoG := G.Mul(x)
		test := result.Sub(xLoG)

		compressedKey := getCompressedKeyString(test)
		if xHiMultiplied, ok := teg.mapping[compressedKey]; ok {
			// If the xHi value found is larger than 2^maxBits, it is not valid.
			if xHiMultiplied > (1 << maxBits) {
				continue
			}
			xComputed := xHiMultiplied + i
			return big.NewInt(int64(xComputed)), nil
		}
	}

	return nil, fmt.Errorf("could not find x")
}

// updateIterMap Helper function to create large maps used by the decryption funciton.
// Constructs the mapping of x_hi * 2^(maxBits/2) * G  : x_hi * (maxBits/2) for all values of x_hi.
// This table can then be used to find x_lo.
func (teg TwistedElGamal) updateIterMap(maxBits MaxBits) {
	G := teg.GetG()

	shift := uint(maxBits) / 2
	for i := 0; i < 1<<shift-1; i++ {
		// Shift i left by shift bits to multiply by 2^shift
		xhiMultipliedValue := i << shift
		xhiMultiplied := new(big.Int).SetUint64(uint64(xhiMultipliedValue))
		x_hi, _ := teg.curve.Scalar.SetBigInt(xhiMultiplied)

		key := G.Mul(x_hi)
		compressedKey := getCompressedKeyString(key)
		teg.mapping[compressedKey] = uint64(xhiMultipliedValue)
	}
}

// DecryptLargeNumber Optimistically decrypt up to a 48 bit number.
// Since creating the map for a 48 bit number takes a large amount of time, we work our way up in hopes that we find
// the answer before having to create the 48 bit map.
func (teg TwistedElGamal) DecryptLargeNumber(sk curves.Scalar, ct *Ciphertext, maxBits MaxBits) (*big.Int, error) {
	if maxBits > MaxBits48 {
		return nil, fmt.Errorf("maxBits must be at most 48, provided (%d)", maxBits)
	}
	values := []MaxBits{MaxBits16, MaxBits32, MaxBits40, MaxBits48}
	for _, bits := range values {
		if bits > maxBits {
			return nil, fmt.Errorf("failed to find value")
		}

		res, err := teg.Decrypt(sk, ct, bits)
		if err == nil {
			return res, nil
		}
	}

	return nil, fmt.Errorf("failed to find value")
}

func getCompressedKeyString(key curves.Point) string {
	compressedKey := key.ToAffineCompressed()
	return string(compressedKey)
}
