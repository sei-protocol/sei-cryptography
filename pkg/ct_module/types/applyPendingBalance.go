package types

import (
	"math/big"

	"github.com/sei-protocol/sei-cryptography/pkg/encryption"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
)

// ApplyPendingBalance is a message to apply the pending balance to the available balance
type ApplyPendingBalance struct {
	Address                        string
	Denom                          string
	NewDecryptableAvailableBalance string
	CurrentPendingBalanceCounter   uint32
	CurrentAvailableBalance        *elgamal.Ciphertext
}

// NewApplyPendingBalance creates a new MsgApplyPendingBalance instance
func NewApplyPendingBalance(
	signedDenom []byte,
	address,
	denom,
	currentDecryptableBalance string,
	currentPendingBalanceCounter uint16,
	currentAvailableBalance,
	currentPendingBalanceLo,
	currentPendingBalanceHi *elgamal.Ciphertext) (*ApplyPendingBalance, error) {
	aesKey, err := encryption.GetAESKey(signedDenom)
	if err != nil {
		return nil, err
	}

	// Get the current balance from the decryptable balance.
	currentBalance, err := encryption.DecryptAESGCM(currentDecryptableBalance, aesKey)
	if err != nil {
		return nil, err
	}

	teg := elgamal.NewTwistedElgamal()
	keyPair, err := teg.KeyGen(signedDenom)
	if err != nil {
		return nil, err
	}

	// Calculate the pending balances that we need to add to the available balance.
	loBalance, err := teg.DecryptLargeNumber(keyPair.PrivateKey, currentPendingBalanceLo, elgamal.MaxBits32)
	if err != nil {
		return nil, err
	}

	hiBalance, err := teg.DecryptLargeNumber(keyPair.PrivateKey, currentPendingBalanceHi, elgamal.MaxBits48)
	if err != nil {
		return nil, err
	}

	// Get the pending balance by combining the lo and hi bits
	pendingBalance := CombinePendingBalances(loBalance, hiBalance)

	// Sum the balances to get the new available balance
	newDecryptedAvailableBalance := new(big.Int).Add(currentBalance, pendingBalance)

	// Encrypt the new available balance
	newDecryptableAvailableBalance, err := encryption.EncryptAESGCM(newDecryptedAvailableBalance, aesKey)
	if err != nil {
		return nil, err
	}

	return &ApplyPendingBalance{
		Address:                        address,
		Denom:                          denom,
		NewDecryptableAvailableBalance: newDecryptableAvailableBalance,
		CurrentPendingBalanceCounter:   uint32(currentPendingBalanceCounter),
		CurrentAvailableBalance:        currentAvailableBalance,
	}, nil
}
