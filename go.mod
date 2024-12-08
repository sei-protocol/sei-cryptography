module github.com/sei-protocol/sei-cryptography

go 1.22

toolchain go1.23.3

require (
	github.com/bwesterb/go-ristretto v1.2.3
	github.com/coinbase/kryptology v1.8.0
	github.com/ethereum/go-ethereum v1.14.12
	github.com/gtank/merlin v0.1.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.27.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/bits-and-blooms/bitset v1.13.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.12.1 // indirect
	github.com/crate-crypto/go-ipa v0.0.0-20240223125850-b1e8a79f509c // indirect
	github.com/crate-crypto/go-kzg-4844 v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/ethereum/c-kzg-4844 v1.0.0 // indirect
	github.com/ethereum/go-verkle v0.1.1-0.20240829091221-dffa7562dbe9 // indirect
	github.com/holiman/uint256 v1.3.1 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20181016162300-f8f6d4d2b643 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/supranational/blst v0.3.13 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/coinbase/kryptology => github.com/sei-protocol/coinbase-kryptology v0.0.0-20241015231206-08f61b7965cd
