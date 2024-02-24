package oauth2

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/go-jose/go-jose/v3"
	"io"
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

	for index, rawKey := range keys {
		var (
			block *pem.Block
			kid   string
			key   = strings.TrimSpace(rawKey)
		)
		if strings.HasPrefix(key, "-----BEGIN ") {
			block, _ = pem.Decode([]byte(key))
			kid = fmt.Sprintf("key%d", index+1)
		} else if strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
			log.Printf("GET %s", key)
			if resp, err := http.Get(key); err == nil && resp.StatusCode == http.StatusOK {
				var jwksBytes []byte
				jwksBytes, err = io.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				var jwks []jose.JSONWebKey
				jwks, err = UnmarshalJWKS(jwksBytes)
				if err != nil {
					return nil, err
				}
				jwksKeys := ToPublicKeys(jwks)
				for jwkid, jwkey := range jwksKeys {
					publicKeys[jwkid] = jwkey
				}
				continue
			} else {
				if err != nil {
					return nil, err
				} else {
					return nil, fmt.Errorf("%s", resp.Status)
				}
			}
		} else {
			var filename string
			if strings.HasPrefix(key, "@") {
				filename = filepath.Join(basePath, key[1:])
			} else {
				filename = filepath.Join(basePath, key)
			}
			bytes, err := os.ReadFile(filename)
			if err != nil {
				return nil, err
			}

			if strings.HasSuffix(strings.ToLower(filename), ".json") {
				var jwks []jose.JSONWebKey
				jwks, err = UnmarshalJWKS(bytes)
				if err != nil {
					return nil, err
				}
				jwksKeys := ToPublicKeys(jwks)
				for jwkid, jwkey := range jwksKeys {
					publicKeys[jwkid] = jwkey
				}
				continue
			}

			block, _ = pem.Decode(bytes)
			kid = strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
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

func UnmarshalJWKS(bytes []byte) ([]jose.JSONWebKey, error) {
	var rawJwks map[string][]map[string]any

	if err := json.Unmarshal(bytes, &rawJwks); err != nil {
		return nil, err
	}

	var jwks []jose.JSONWebKey

	for _, rawJwk := range rawJwks["keys"] {
		var jwkBytes, _ = json.Marshal(rawJwk)
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
			return nil, err
		}
		jwks = append(jwks, jwk)
	}
	return jwks, nil
}
