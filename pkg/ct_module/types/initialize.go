package types

import (
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/sei-protocol/sei-cryptography/pkg/zkproofs"
)

type InitializeAccount struct {
	FromAddress        string                   `json:"from_address"`
	Denom              string                   `json:"denom"`
	Pubkey             *curves.Point            `json:"pubkey"`
	PendingBalanceLo   *elgamal.Ciphertext      `json:"pending_balance_lo"`
	PendingBalanceHi   *elgamal.Ciphertext      `json:"pending_balance_hi"`
	AvailableBalance   *elgamal.Ciphertext      `json:"available_balance"`
	DecryptableBalance string                   `json:"decryptable_balance"`
	Proofs             *InitializeAccountProofs `json:"proofs"`
}

type InitializeAccountProofs struct {
	PubkeyValidityProof       *zkproofs.PubKeyValidityProof `json:"pubkey_validity_proof"`
	ZeroPendingBalanceLoProof *zkproofs.ZeroBalanceProof    `json:"zero_pending_balance_lo_proof"`
	ZeroPendingBalanceHiProof *zkproofs.ZeroBalanceProof    `json:"zero_pending_balance_hi_proof"`
	ZeroAvailableBalanceProof *zkproofs.ZeroBalanceProof    `json:"zero_available_balance_proof"`
}

func NewInitializeAccount(signedDenom []byte, address, denom string) (*InitializeAccount, error) {
	teg := elgamal.NewTwistedElgamal()
	keys, err := teg.KeyGen(signedDenom)
	if err != nil {
		return nil, err
	}

	aesKey, err := encryption.GetAESKey(signedDenom)
	if err != nil {
		return nil, err
	}

	// Encrypt the 0 value using the aesKey
	decryptableBalance, err := encryption.EncryptAESGCM(big.NewInt(0), aesKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the 0 value thrice using the public key for the account balances.
	zeroCiphertextLo, _, err := teg.Encrypt(keys.PublicKey, big.NewInt(0))
	if err != nil {
		return nil, err
	}

	zeroCiphertextHi, _, err := teg.Encrypt(keys.PublicKey, big.NewInt(0))
	if err != nil {
		return nil, err
	}

	zeroCiphertextAvailable, _, err := teg.Encrypt(keys.PublicKey, big.NewInt(0))
	if err != nil {
		return nil, err
	}

	pubkeyValidityProof, err := zkproofs.NewPubKeyValidityProof(keys.PublicKey, keys.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Generate proofs for the zero values
	proofLo, err := zkproofs.NewZeroBalanceProof(keys, zeroCiphertextLo)
	if err != nil {
		return nil, err
	}

	proofHi, err := zkproofs.NewZeroBalanceProof(keys, zeroCiphertextHi)
	if err != nil {
		return nil, err
	}

	proofAvailable, err := zkproofs.NewZeroBalanceProof(keys, zeroCiphertextAvailable)
	if err != nil {
		return nil, err
	}

	proofs := InitializeAccountProofs{
		PubkeyValidityProof:       pubkeyValidityProof,
		ZeroPendingBalanceLoProof: proofLo,
		ZeroPendingBalanceHiProof: proofHi,
		ZeroAvailableBalanceProof: proofAvailable,
	}

	return &InitializeAccount{
		FromAddress:        address,
		Denom:              denom,
		Pubkey:             &keys.PublicKey,
		DecryptableBalance: decryptableBalance,
		PendingBalanceLo:   zeroCiphertextLo,
		PendingBalanceHi:   zeroCiphertextHi,
		AvailableBalance:   zeroCiphertextAvailable,
		Proofs:             &proofs,
	}, nil
}
