package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	jose "gopkg.in/square/go-jose.v2"
)

func Jwks(w http.ResponseWriter, r *http.Request) {
	response, err := json.Marshal(
		jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:   &rsaPrivKey.PublicKey,
					KeyID: "jwtokerKey",
					Use:   "sig",
				},
			},
		},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "Error marshaling: %s\n", err)
		return
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "Error writing response: %s\n", err)
		return
	}
}
