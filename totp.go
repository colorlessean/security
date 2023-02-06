package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

func generateTOTP(key []byte, time, returnDigits, crypto string) (string, error) {
	algorithms := map[string]func() hash.Hash{
		"sha1":   sha1.New,
		"sha256": sha256.New,
		"sha512": sha512.New,
	}

	algorithm, found := algorithms[crypto]
	if !found {
		return "", errors.New("invalid input")
	}

	mac := hmac.New(algorithm, key)

	var message []byte
	mac.Write(message)

	return "", nil
}
