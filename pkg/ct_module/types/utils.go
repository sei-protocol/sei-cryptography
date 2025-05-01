package types

import "math/big"

func CombinePendingBalances(loBits *big.Int, hiBits *big.Int) *big.Int {
	// Shift the hi bits by 16 bits to the left
	hiBits.Lsh(hiBits, 16) // Equivalent to hi << 16

	// Combine by adding hiBig with loBig
	combined := new(big.Int).Add(hiBits, loBits)
	return combined
}
