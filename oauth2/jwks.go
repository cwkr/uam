package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"log"
	"net/http"
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

func JwksHandler(publicKeys ...*rsa.PublicKey) http.Handler {
	var keys = make([]jose.JSONWebKey, 0, len(publicKeys))
	for i, publicKey := range publicKeys {
		keys = append(keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: fmt.Sprintf("jwk%03d", i+1),
			Use:   "sig",
		})
	}
	return &jwksHandler{keySet: jose.JSONWebKeySet{Keys: keys}}
}
