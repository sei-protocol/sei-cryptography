module github.com/sei-protocol/sei-cryptography

go 1.21

require (
	github.com/bwesterb/go-ristretto v1.2.3
	github.com/coinbase/kryptology v1.8.0
	github.com/gtank/merlin v0.1.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.27.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20181016162300-f8f6d4d2b643 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/coinbase/kryptology => github.com/sei-protocol/coinbase-kryptology v0.0.0-20241210171554-278d19024e41
