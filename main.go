package main

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	rsaPrivKey *rsa.PrivateKey
	config *JwtokerConfig
	signer jose.Signer
)

func main() {
	var err error
	var configFilename string
	var showHelp bool
	var initConfig bool

	rand.Seed(time.Now().UTC().UnixNano())

	flag.StringVar(&configFilename, "config", "jwtoker.json", "config file")
	flag.BoolVar(&showHelp, "help", false, "print help and exit")
	flag.BoolVar(&initConfig, "init", false, "init config and exit")
	flag.Parse()

	if showHelp {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set defaults
	config = &JwtokerConfig{
		Port:     1337,
		Username: "jwtoker",
	}

	configBytes, err := os.ReadFile(configFilename)
	if err != nil {
		log.Print(err)
	} else {
		err = json.Unmarshal(configBytes, config)
		if err != nil {
			log.Fatal(err)
		}
	}

	if strings.HasPrefix(config.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(config.Key))
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	} else if config.Key == "" || !FileExists(config.Key) {
		if !initConfig && config.Key != "" {
			log.Fatal("Missing key", config.Key)
		}
		rsaPrivKey, err = rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}

		pubASN1 := x509.MarshalPKCS1PrivateKey(rsaPrivKey)
		keyBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pubASN1,
		})
		if config.Key == "" {
			config.Key = string(keyBytes)
		} else {
			err := os.WriteFile(config.Key, keyBytes, 0600)
			if err != nil {
				log.Fatal(err)
			}
		}

	} else {
		pemBytes, err := os.ReadFile(config.Key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(pemBytes)
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	}

	signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivKey}, nil)
	if err != nil {
		log.Fatal(err)
	}

	if initConfig {
		log.Printf("Initializing config file %s...", configFilename)
		configJson, _ := json.MarshalIndent(config, "", "  ")
		err := os.WriteFile(configFilename, configJson, 0644)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	http.HandleFunc("/", Index)
	http.HandleFunc("/jwks", Jwks)
	http.HandleFunc("/auth", Auth)
	http.HandleFunc("/favicon.ico", Favicon)

	log.Printf("Started listening on http://localhost:%d/...", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", config.Port), nil))
}
