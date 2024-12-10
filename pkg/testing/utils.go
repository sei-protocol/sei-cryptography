package testing

import (
	"time"
)

// GenerateKey generates a new private bytes object used to dervie the keypair.
func GenerateKey() *[]byte {
	result := []byte(time.Now().String())
	return &result
}
