package model

import (
	"encoding/hex"
)

// decodeHex decodes a hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
