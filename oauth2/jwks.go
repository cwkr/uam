package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type jwksHandler struct {
	keySet jose.JSONWebKeySet
}

func (j *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var bytes, err = json.Marshal(j.keySet)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error marshaling: %s\n", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func LoadPublicKeys(keys []string) (map[string]*rsa.PublicKey, error) {
	var rsaPublicKeys = make(map[string]*rsa.PublicKey)

	for i, key := range keys {
		var (
			block *pem.Block
			kid   string
		)
		if strings.HasPrefix(key, "-----BEGIN ") {
			block, _ = pem.Decode([]byte(key))
			kid = fmt.Sprintf("key%d", i+1)
		} else {
			bytes, err := os.ReadFile(key)
			if err != nil {
				return nil, err
			}
			block, _ = pem.Decode(bytes)
			kid = strings.TrimSuffix(filepath.Base(key), filepath.Ext(key))
		}

		var rsaPublicKey *rsa.PublicKey

		switch strings.TrimSpace(strings.ToLower(block.Type)) {
		case "rsa private key":
			rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPublicKey = &rsaPrivateKey.PublicKey
		case "rsa public key":
			var err error
			rsaPublicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("Unsupported key type: " + block.Type)
		}

		rsaPublicKeys[kid] = rsaPublicKey
	}

	return rsaPublicKeys, nil
}

// ToJwks creates JSON Web Keys from multiple RSA public keys
func ToJwks(publicKeys map[string]*rsa.PublicKey) []jose.JSONWebKey {
	var keys = make([]jose.JSONWebKey, 0, len(publicKeys))
	for kid, publicKey := range publicKeys {
		keys = append(keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: kid,
			Use:   "sig",
		})
	}
	return keys
}

func JwksHandler(publicKeys map[string]*rsa.PublicKey) http.Handler {
	return &jwksHandler{
		keySet: jose.JSONWebKeySet{
			Keys: ToJwks(publicKeys),
		},
	}
}
