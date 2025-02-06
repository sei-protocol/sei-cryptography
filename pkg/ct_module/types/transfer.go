package types

import (
	"errors"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption"
	"github.com/sei-protocol/sei-cryptography/pkg/encryption/elgamal"
	"github.com/sei-protocol/sei-cryptography/pkg/zkproofs"
)

type Transfer struct {
	FromAddress                string              `json:"from_address"`
	ToAddress                  string              `json:"to_address"`
	Denom                      string              `json:"denom"`
	SenderTransferAmountLo     *elgamal.Ciphertext `json:"sender_transfer_amount_lo"`
	SenderTransferAmountHi     *elgamal.Ciphertext `json:"sender_transfer_amount_hi"`
	RecipientTransferAmountLo  *elgamal.Ciphertext `json:"recipient_transfer_amount_lo"`
	RecipientTransferAmountHi  *elgamal.Ciphertext `json:"recipient_transfer_amount_hi"`
	RemainingBalanceCommitment *elgamal.Ciphertext `json:"remaining_balance_commitment"`
	DecryptableBalance         string              `json:"decryptable_balance"`
	Proofs                     *TransferProofs     `json:"proofs"`
	Auditors                   []*TransferAuditor  `json:"auditors,omitempty"` //optional field
}

type TransferProofs struct {
	RemainingBalanceCommitmentValidityProof *zkproofs.CiphertextValidityProof           `json:"remaining_balance_commitment_validity_proof"`
	SenderTransferAmountLoValidityProof     *zkproofs.CiphertextValidityProof           `json:"sender_transfer_amount_lo_validity_proof"`
	SenderTransferAmountHiValidityProof     *zkproofs.CiphertextValidityProof           `json:"sender_transfer_amount_hi_validity_proof"`
	RecipientTransferAmountLoValidityProof  *zkproofs.CiphertextValidityProof           `json:"recipient_transfer_amount_lo_validity_proof"`
	RecipientTransferAmountHiValidityProof  *zkproofs.CiphertextValidityProof           `json:"recipient_transfer_amount_hi_validity_proof"`
	RemainingBalanceRangeProof              *zkproofs.RangeProof                        `json:"remaining_balance_range_proof"`
	RemainingBalanceEqualityProof           *zkproofs.CiphertextCommitmentEqualityProof `json:"remaining_balance_equality_proof"`
	TransferAmountLoEqualityProof           *zkproofs.CiphertextCiphertextEqualityProof `json:"transfer_amount_lo_equality_proof"`
	TransferAmountHiEqualityProof           *zkproofs.CiphertextCiphertextEqualityProof `json:"transfer_amount_hi_equality_proof"`
}

type TransferAuditor struct {
	Address                       string                                      `json:"address"`
	EncryptedTransferAmountLo     *elgamal.Ciphertext                         `json:"encrypted_transfer_amount_lo"`
	EncryptedTransferAmountHi     *elgamal.Ciphertext                         `json:"encrypted_transfer_amount_hi"`
	TransferAmountLoValidityProof *zkproofs.CiphertextValidityProof           `json:"transfer_amount_lo_validity_proof"`
	TransferAmountHiValidityProof *zkproofs.CiphertextValidityProof           `json:"transfer_amount_hi_validity_proof"`
	TransferAmountLoEqualityProof *zkproofs.CiphertextCiphertextEqualityProof `json:"transfer_amount_lo_equality_proof"`
	TransferAmountHiEqualityProof *zkproofs.CiphertextCiphertextEqualityProof `json:"transfer_amount_hi_equality_proof"`
}

type CtAuditor struct {
	AuditorAddress                string `json:"auditorAddress"`
	EncryptedTransferAmountLo     []byte `json:"encryptedTransferAmountLo"`
	EncryptedTransferAmountHi     []byte `json:"encryptedTransferAmountHi"`
	TransferAmountLoValidityProof []byte `json:"transferAmountLoValidityProof"`
	TransferAmountHiValidityProof []byte `json:"transferAmountHiValidityProof"`
	TransferAmountLoEqualityProof []byte `json:"transferAmountLoEqualityProof"`
	TransferAmountHiEqualityProof []byte `json:"transferAmountHiEqualityProof"`
}

type AuditorInput struct {
	Address string
	Pubkey  *curves.Point
}

// NewTransfer creates a new Transfer object.
func NewTransfer(
	signedDenom []byte,
	senderAddr,
	recipientAddr,
	denom,
	senderCurrentDecryptableBalance string,
	senderCurrentAvailableBalance *elgamal.Ciphertext,
	amount uint64,
	recipientPubkey *curves.Point,
	auditors []AuditorInput) (*Transfer, error) {
	if signedDenom == nil {
		return &Transfer{}, errors.New("private key is required")
	}

	if senderAddr == "" {
		return &Transfer{}, errors.New("sender address is required")
	}

	if recipientAddr == "" {
		return &Transfer{}, errors.New("recipient address is required")
	}

	if senderAddr == recipientAddr {
		return &Transfer{}, errors.New("sender and recipient addresses cannot be the same")
	}

	if denom == "" {
		return &Transfer{}, errors.New("denom is required")
	}

	if senderCurrentAvailableBalance == nil {
		return &Transfer{}, errors.New("available balance is required")
	}

	if recipientPubkey == nil {
		return &Transfer{}, errors.New("recipient public key is required")
	}

	// Get the current balance of the account from the decryptableBalance
	aesKey, err := encryption.GetAESKey(signedDenom)
	if err != nil {
		return &Transfer{}, err
	}

	currentBalance, err := encryption.DecryptAESGCM(senderCurrentDecryptableBalance, aesKey)
	if err != nil {
		return &Transfer{}, err
	}

	bigIntAmount := new(big.Int).SetUint64(amount)
	// Check that account has sufficient balance to make the transfer.
	if currentBalance.Cmp(bigIntAmount) == -1 {
		return &Transfer{}, errors.New("insufficient balance")
	}

	// Encrypt the new balance using the user's AES Key.
	newBalance := new(big.Int).Sub(currentBalance, bigIntAmount)
	decryptableNewBalance, err := encryption.EncryptAESGCM(newBalance, aesKey)
	if err != nil {
		return &Transfer{}, err
	}

	// Now we want to encrypt the commitment to the new balance. This is used to generate the range proof.
	teg := elgamal.NewTwistedElgamal()
	senderKeyPair, err := teg.KeyGen(signedDenom)
	if err != nil {
		return &Transfer{}, err
	}

	newBalanceCommitment, newBalanceRandomness, err := teg.Encrypt(senderKeyPair.PublicKey, newBalance)
	if err != nil {
		return &Transfer{}, err
	}

	// Split the transfer amount into bottom 16 bits and top 32 bits.
	// Extract the bottom 16 bits (rightmost 16 bits)
	transferLoBits, transferHiBits, err := SplitTransferBalance(amount)
	if err != nil {
		return &Transfer{}, err
	}
	loBitsBigInt := new(big.Int).SetUint64(uint64(transferLoBits))
	hiBitsBigInt := new(big.Int).SetUint64(uint64(transferHiBits))

	// Encrypt the transfer amounts for the sender
	senderEncryptedTransferLoBits, senderLoBitsRandomness, err := teg.Encrypt(senderKeyPair.PublicKey, loBitsBigInt)
	if err != nil {
		return &Transfer{}, err
	}

	senderEncryptedTransferHiBits, senderHiBitsRandomness, err := teg.Encrypt(senderKeyPair.PublicKey, hiBitsBigInt)
	if err != nil {
		return &Transfer{}, err
	}

	// Now that we have all the params we need, start generating the proofs wrt the Sender params.
	// First we generate validity proofs that all the ciphertexts are valid.
	newCommitmentValidityProof, err := zkproofs.NewCiphertextValidityProof(&newBalanceRandomness, senderKeyPair.PublicKey, newBalanceCommitment, newBalance)
	if err != nil {
		return &Transfer{}, err
	}

	senderLoBitsValidityProof, err := zkproofs.NewCiphertextValidityProof(&senderLoBitsRandomness, senderKeyPair.PublicKey, senderEncryptedTransferLoBits, loBitsBigInt)
	if err != nil {
		return &Transfer{}, err
	}

	senderHiBitsValidityProof, err := zkproofs.NewCiphertextValidityProof(&senderHiBitsRandomness, senderKeyPair.PublicKey, senderEncryptedTransferHiBits, hiBitsBigInt)
	if err != nil {
		return &Transfer{}, err
	}

	// Secondly, we generate a Range Proof to prove that the PedersonCommitment to the new balance is greater than zero.
	newBalanceRangeProof, err := zkproofs.NewRangeProof(128, newBalance, newBalanceRandomness)
	if err != nil {
		return &Transfer{}, err
	}

	// Thirdly we generate proof that the PedersonCommitment we generated encrypts the same value as AvailableBalance - TransferAmount
	newBalanceScalar, err := curves.ED25519().Scalar.SetBigInt(newBalance)
	if err != nil {
		return &Transfer{}, err
	}

	newBalanceCiphertext, err := teg.SubWithLoHi(senderCurrentAvailableBalance, senderEncryptedTransferLoBits, senderEncryptedTransferHiBits)
	if err != nil {
		return &Transfer{}, err
	}

	commitmentCiphertextEqualityProof, err := zkproofs.NewCiphertextCommitmentEqualityProof(senderKeyPair, newBalanceCiphertext, &newBalanceRandomness, &newBalanceScalar)
	if err != nil {
		return &Transfer{}, err
	}

	// Now, we create params and proofs specific to the recipient
	recipientParams, err := createTransferPartyParams(recipientAddr, loBitsBigInt, hiBitsBigInt, senderKeyPair, senderEncryptedTransferLoBits, senderEncryptedTransferHiBits, recipientPubkey)
	if err != nil {
		return &Transfer{}, err
	}

	proofs := TransferProofs{
		RemainingBalanceCommitmentValidityProof: newCommitmentValidityProof,
		SenderTransferAmountLoValidityProof:     senderLoBitsValidityProof,
		SenderTransferAmountHiValidityProof:     senderHiBitsValidityProof,
		RecipientTransferAmountLoValidityProof:  recipientParams.TransferAmountLoValidityProof,
		RecipientTransferAmountHiValidityProof:  recipientParams.TransferAmountHiValidityProof,
		RemainingBalanceRangeProof:              newBalanceRangeProof,
		RemainingBalanceEqualityProof:           commitmentCiphertextEqualityProof,
		TransferAmountLoEqualityProof:           recipientParams.TransferAmountLoEqualityProof,
		TransferAmountHiEqualityProof:           recipientParams.TransferAmountHiEqualityProof,
	}

	// Lastly we generate the Auditor parameters, if required.
	auditorsData := []*TransferAuditor{}
	for _, auditor := range auditors {
		auditorData, err := createTransferPartyParams(auditor.Address, loBitsBigInt, hiBitsBigInt, senderKeyPair, senderEncryptedTransferLoBits, senderEncryptedTransferHiBits, auditor.Pubkey)
		if err != nil {
			return &Transfer{}, err
		}
		auditorsData = append(auditorsData, auditorData)
	}

	return &Transfer{
		FromAddress:                senderAddr,
		ToAddress:                  recipientAddr,
		Denom:                      denom,
		SenderTransferAmountLo:     senderEncryptedTransferLoBits,
		SenderTransferAmountHi:     senderEncryptedTransferHiBits,
		RecipientTransferAmountLo:  recipientParams.EncryptedTransferAmountLo,
		RecipientTransferAmountHi:  recipientParams.EncryptedTransferAmountHi,
		RemainingBalanceCommitment: newBalanceCommitment,
		DecryptableBalance:         decryptableNewBalance,
		Proofs:                     &proofs,
		Auditors:                   auditorsData,
	}, nil
}

func createTransferPartyParams(
	partyAddress string,
	transferLoBits *big.Int,
	transferHiBits *big.Int,
	senderKeyPair *elgamal.KeyPair,
	senderEncryptedTransferLoBits,
	senderEncryptedTransferHiBits *elgamal.Ciphertext,
	partyPubkey *curves.Point) (*TransferAuditor, error) {
	teg := elgamal.NewTwistedElgamal()

	// Encrypt the transfer amounts using the party's public key.
	encryptedTransferLoBits, loBitsRandomness, err := teg.Encrypt(*partyPubkey, transferLoBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	encryptedTransferHiBits, hiBitsRandomness, err := teg.Encrypt(*partyPubkey, transferHiBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	// Create validity proofs that the ciphertexts are valid (encrypted with the correct pubkey).
	loBitsValidityProof, err := zkproofs.NewCiphertextValidityProof(&loBitsRandomness, *partyPubkey, encryptedTransferLoBits, transferLoBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	hiBitsValidityProof, err := zkproofs.NewCiphertextValidityProof(&hiBitsRandomness, *partyPubkey, encryptedTransferHiBits, transferHiBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	// Lastly, we need to generate proof that the ciphertexts of the transfer amounts encrypt the same value as those for the sender.
	loBitsScalar, err := curves.ED25519().Scalar.SetBigInt(transferLoBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	hiBitsScalar, err := curves.ED25519().Scalar.SetBigInt(transferHiBits)
	if err != nil {
		return &TransferAuditor{}, err
	}

	ciphertextLoEqualityProof, err := zkproofs.NewCiphertextCiphertextEqualityProof(senderKeyPair, partyPubkey, senderEncryptedTransferLoBits, &loBitsRandomness, &loBitsScalar)
	if err != nil {
		return &TransferAuditor{}, err
	}

	ciphertextHiEqualityProof, err := zkproofs.NewCiphertextCiphertextEqualityProof(senderKeyPair, partyPubkey, senderEncryptedTransferHiBits, &hiBitsRandomness, &hiBitsScalar)
	if err != nil {
		return &TransferAuditor{}, err
	}

	return &TransferAuditor{
		Address:                       partyAddress,
		EncryptedTransferAmountLo:     encryptedTransferLoBits,
		EncryptedTransferAmountHi:     encryptedTransferHiBits,
		TransferAmountLoValidityProof: loBitsValidityProof,
		TransferAmountHiValidityProof: hiBitsValidityProof,
		TransferAmountLoEqualityProof: ciphertextLoEqualityProof,
		TransferAmountHiEqualityProof: ciphertextHiEqualityProof,
	}, nil
}

// SplitTransferBalance splits some amount (maximum of 48 bit) into two parts: the bottom 16 bits and the next 32 bits
func SplitTransferBalance(amount uint64) (uint16, uint32, error) {

	// The maximum transfer amount is 48 bits.
	maxAmount := uint64((1 << 48) - 1)

	if amount > maxAmount {
		return 0, 0, errors.New("amount is too large")
	}

	// Extract the bottom 16 bits (rightmost 16 bits)
	bottom16 := uint16(amount & 0xFFFF)

	// Extract the next 32 bits (from bit 16 to bit 47) (Everything else is ignored since the max is 48 bits)
	next32 := uint32((amount >> 16) & 0xFFFFFFFF)

	return bottom16, next32, nil
}
