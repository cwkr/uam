package oauth2

import (
	"crypto/rsa"
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

func LoadPublicKeys(basePath string, keys []string) (map[string]*rsa.PublicKey, error) {
	var rsaPublicKeys = make(map[string]*rsa.PublicKey)

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
		case "public key":
			var err error
			var ok bool
			var k any
			k, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPublicKey, ok = k.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("only rsa keys are supported")
			}
		default:
			return nil, errors.New("unsupported key type: " + block.Type)
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
