package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func GeneratePrivateKey(keySize int) (*rsa.PrivateKey, []byte, error) {
	var rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}

	asn1 := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: asn1,
	})

	return rsaPrivateKey, bytes, nil
}
