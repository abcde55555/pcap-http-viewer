package repeater

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
