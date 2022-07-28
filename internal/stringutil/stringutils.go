package stringutil

import (
	"crypto/rand"
	"encoding/base64"
)

func IsAnyEmpty(strings ...string) bool {
	for _, s := range strings {
		if s == "" {
			return true
		}
	}
	return false
}

func RandomBytesString(max int) string {
	var bytes = make([]byte, max)

	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes)
}
