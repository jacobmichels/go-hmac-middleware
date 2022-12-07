package hmacmiddleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func Sign(msg, key []byte) []byte {
	mac := writeMac(msg, key)

	return mac.Sum(nil)
}

func verify(msg, key, sig []byte) bool {
	mac := writeMac(msg, key)

	return hmac.Equal(sig, mac.Sum(nil))
}

func writeMac(msg, key []byte) hash.Hash {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return mac
}
