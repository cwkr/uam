package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

func Verify(codeChallenge, codeVerifier string) bool {
	var verifierBytes = sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(verifierBytes[:]) == codeChallenge
}

func CodeChallange(codeVerifier string) string {
	var byteArray = sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(byteArray[:])
}
