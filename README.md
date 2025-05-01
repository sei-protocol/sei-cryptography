# Sei Cryptography

## Description
A library for encryption and zero knowledge proofs.

## Packages
This library is split into 3 packages

### Encryption
This package contains a simple library for encryption and decryption of numbers
It includes
- Twisted El Gamal key generation, encryption and decryption
- Regular AES-GCM key generation, encryption and decryption

### zkproofs
The zkproofs package contains methods to create and verify zero knowledge proofs on values encrypted 
by Twisted El Gamal encryption. It includes
- Public Key Validity Proof
- Ciphertext Validity Proof
- Ciphertext Ciphertext Equality Proof
- Ciphertext Commitment Equality Proof
- Range Proofs
- Zero Proofs

### ct_module
The ct_module package contains methods to create instructions used in Sei's Confidential Transfers Module.

If you are looking to send messages to Sei's confidential transfers module, you should import types directly from
sei-chain instead since it contains all the methods required to convert these instructions to their proto form.