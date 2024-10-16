package elgamal

import (
	"fmt"
	"math/big"
)

// AddScalar Adds a scalar value to some ciphertext
// For some Ciphertext that encodes x, (C = rH + xG, D = rP), we can just add amount*G to C.
// The new Ciphertext C' will encode C' = rH + xG + amountG = rH + (x+amount)G.
// We do not need to touch D, since the randomness has not changed.
func (teg TwistedElGamal) AddScalar(ciphertext *Ciphertext, amount uint64) (*Ciphertext, error) {
	G := teg.GetG()
	// Create a scalar from the amount.
	bigIntAmount := new(big.Int).SetUint64(amount)
	scalarAmount, err := teg.curve.Scalar.SetBigInt(bigIntAmount)
	if err != nil {
		return nil, err
	}

	// Multiply the amount by G
	amountG := G.Mul(scalarAmount)

	newC := ciphertext.C.Add(amountG)
	return &Ciphertext{
		C: newC,
		D: ciphertext.D,
	}, nil
}

// SubScalar Subtracts a scalar value to some ciphertext
// For some Ciphertext that encodes x, (C = rH + xG, D = rP), we can just sub amount*G to C.
// The new Ciphertext C' will encode C' = rH + xG - amountG = rH + (x-amount)G.
// We do not need to touch D, since the randomness has not changed.
func (teg TwistedElGamal) SubScalar(ciphertext *Ciphertext, amount uint64) (*Ciphertext, error) {
	G := teg.GetG()
	// Create a scalar from the amount.
	bigIntAmount := new(big.Int).SetUint64(amount)
	scalarAmount, err := teg.curve.Scalar.SetBigInt(bigIntAmount)
	if err != nil {
		return nil, err
	}

	// Multiply the amount by G
	amountG := G.Mul(scalarAmount)

	newC := ciphertext.C.Sub(amountG)
	return &Ciphertext{
		C: newC,
		D: ciphertext.D,
	}, nil
}

// AddCiphertext Add takes two ciphertexts and returns the ciphertext of their sum.
func AddCiphertext(ct1 *Ciphertext, ct2 *Ciphertext) (*Ciphertext, error) {
	// cSum = C1 + C2
	cSum := ct1.C.Add(ct2.C)

	// Dsum = D1 + D2
	dSum := ct1.D.Add(ct2.D)

	return &Ciphertext{
		C: cSum,
		D: dSum,
	}, nil
}

// SubtractCiphertext Subtract takes two ciphertexts and returns the ciphertext of their difference.
func SubtractCiphertext(ct1 *Ciphertext, ct2 *Ciphertext) (*Ciphertext, error) {
	// Cdiff = C1 - C2
	cDiff := ct1.C.Sub(ct2.C)

	// Ddiff = D1 - D2
	dDiff := ct1.D.Sub(ct2.D)

	return &Ciphertext{
		C: cDiff,
		D: dDiff,
	}, nil
}

// ScalarMultCiphertext Multiply takes a ciphertext ct and returns the ciphertext of their ct * factor.
func (teg TwistedElGamal) ScalarMultCiphertext(ct *Ciphertext, factor uint64) (*Ciphertext, error) {
	scalarValue := new(big.Int).SetUint64(factor)
	factorScalar, _ := teg.curve.Scalar.SetBigInt(scalarValue)

	// Cmul = C * Factor
	cMul := ct.C.Mul(factorScalar)

	// Dmul = D * Factor
	dMul := ct.D.Mul(factorScalar)

	return &Ciphertext{
		C: cMul,
		D: dMul,
	}, nil
}

// Additional Functions

// AddWithLoHi performs the operation: left_ciphertext + (right_ciphertext_lo + 2^16 * right_ciphertext_hi)
func (teg TwistedElGamal) AddWithLoHi(leftCiphertext, rightCiphertextLo, rightCiphertextHi *Ciphertext) (*Ciphertext, error) {
	// Step 1: Define shift_scalar as 2^16 (which is 65536)
	shiftScalar := 1 << 16

	// Step 2: Shift rightCiphertextHi by multiplying by shift_scalar
	shiftedRightCiphertextHi, err := teg.ScalarMultCiphertext(rightCiphertextHi, uint64(shiftScalar))
	if err != nil {
		return nil, fmt.Errorf("failed to shift rightCiphertextHi: %v", err)
	}

	// Step 3: Add rightCiphertextLo and shiftedRightCiphertextHi
	combinedRightCiphertext, err := AddCiphertext(rightCiphertextLo, shiftedRightCiphertextHi)
	if err != nil {
		return nil, fmt.Errorf("failed to combine right_ciphertext_lo and shifted_right_ciphertext_hi: %v", err)
	}

	// Step 4: Add the result to leftCiphertext
	finalCiphertext, err := AddCiphertext(leftCiphertext, combinedRightCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to add combined_right_ciphertext to left_ciphertext: %v", err)
	}

	// Return the final ciphertext
	return finalCiphertext, nil
}

// SubWithLoHi performs the operation: left_ciphertext - (right_ciphertext_lo + 2^16 * right_ciphertext_hi)
func (teg TwistedElGamal) SubWithLoHi(leftCiphertext, rightCiphertextLo, rightCiphertextHi *Ciphertext) (*Ciphertext, error) {
	// Step 1: Define shift_scalar as 2^16 (which is 65536)
	shiftScalar := 1 << 16

	// Step 2: Shift rightCiphertextHi by multiplying by shift_scalar
	shiftedRightCiphertextHi, err := teg.ScalarMultCiphertext(rightCiphertextHi, uint64(shiftScalar))
	if err != nil {
		return nil, fmt.Errorf("failed to shift rightCiphertextHi: %v", err)
	}

	// Step 3: Add rightCiphertextLo and shiftedRightCiphertextHi
	combinedRightCiphertext, err := AddCiphertext(rightCiphertextLo, shiftedRightCiphertextHi)
	if err != nil {
		return nil, fmt.Errorf("failed to combine right_ciphertext_lo and shifted_right_ciphertext_hi: %v", err)
	}

	// Step 4: Subtract the result from leftCiphertext
	finalCiphertext, err := SubtractCiphertext(leftCiphertext, combinedRightCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to subtract combined_right_ciphertext from left_ciphertext: %v", err)
	}

	// Return the final ciphertext
	return finalCiphertext, nil
}
