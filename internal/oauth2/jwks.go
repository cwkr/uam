package oauth2

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cwkr/auth-server/internal/httputil"
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

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var bytes, err = json.Marshal(j.keySet)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error marshaling: %s\n", err), http.StatusInternalServerError)
		return
	}
	httputil.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func LoadPublicKeys(basePath string, keys []string) (map[string]any, error) {
	var publicKeys = make(map[string]any)

	for i, key := range keys {
		var (
			block *pem.Block
			kid   string
		)
		if strings.HasPrefix(key, "-----BEGIN ") {
			block, _ = pem.Decode([]byte(key))
			kid = fmt.Sprintf("key%d", i+1)
		} else if strings.HasPrefix(key, "@") {
			var filename = filepath.Join(basePath, key[1:])
			bytes, err := os.ReadFile(filename)
			if err != nil {
				return nil, err
			}
			block, _ = pem.Decode(bytes)
			kid = strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		} else {
			return nil, errors.New("cannot load key")
		}

		var publicKey any

		switch strings.TrimSpace(strings.ToLower(block.Type)) {
		case "rsa private key":
			rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			publicKey = &rsaPrivateKey.PublicKey
		case "ec private key":
			ecPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			publicKey = &ecPrivateKey.PublicKey
		case "rsa public key":
			var err error
			publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		case "public key":
			var err error
			publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unsupported key type: " + block.Type)
		}

		publicKeys[kid] = publicKey
	}

	return publicKeys, nil
}

// ToJwks creates JSON Web Keys from multiple public keys
func ToJwks(publicKeys map[string]any) []jose.JSONWebKey {
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

func ToPublicKeys(jwks []jose.JSONWebKey) map[string]any {
	var publicKeys = make(map[string]any, len(jwks))
	for _, jwk := range jwks {
		publicKeys[jwk.KeyID] = jwk.Key
	}
	return publicKeys
}

func JwksHandler(publicKeys map[string]any) http.Handler {
	return &jwksHandler{
		keySet: jose.JSONWebKeySet{
			Keys: ToJwks(publicKeys),
		},
	}
}
