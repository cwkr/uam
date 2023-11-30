package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

const HeaderKeyID = "KeyID"

func GeneratePrivateKey(keySize int, keyID string) ([]byte, error) {
	var rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	asn1 := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: asn1,
	}
	if keyID != "" {
		block.Headers = map[string]string{
			HeaderKeyID: keyID,
		}
	}
	bytes := pem.EncodeToMemory(block)

	return bytes, nil
}
