package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/internal/oauth2"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	var jwksURI string

	log.SetOutput(os.Stdout)

	flag.StringVar(&jwksURI, "jwks", "", "JSON Web Key Set URI")
	flag.Parse()

	var jwksBytes []byte

	if strings.HasPrefix(jwksURI, "http://") || strings.HasPrefix(jwksURI, "https://") {
		if resp, err := http.Get(jwksURI); err == nil && resp.StatusCode == http.StatusOK {
			jwksBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}
		} else {
			if err != nil {
				panic(err)
			} else {
				panic(resp.Status)
			}
		}
	} else {
		var err error
		jwksBytes, err = os.ReadFile(jwksURI)
		if err != nil {
			panic(err)
		}
	}

	var publicKeys map[string]any
	if jwks, err := oauth2.UnmarshalJWKS(jwksBytes); err != nil {
		publicKeys = oauth2.ToPublicKeys(jwks)
	} else {
		panic(err)
	}

	for _, publicKey := range publicKeys {
		var pubASN1, _ = x509.MarshalPKIXPublicKey(publicKey)

		var pubBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		})

		fmt.Print(string(pubBytes))
	}
}
