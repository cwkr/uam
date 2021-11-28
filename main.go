package main

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/jwtoker/oauth2"
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
	tokenService oauth2.TokenService
)

func FileExists(name string) bool {
	stat, err := os.Stat(name)
	if err == nil {
		return !stat.IsDir()
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return false
}

func main() {
	var err error
	var configFilename string
	var showHelp bool
	var initConfig bool

	log.SetOutput(os.Stdout)

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
		Issuer: "http://localhost:1337/",
		Port: 1337,
		Username: "jwtoker",
		ClientID: "myapp",
		AccessTokenLifetime: 3600,
		Claims: map[string]interface{}{"email": "jwtoker@example.org"},
		Scopes: []string{"openid", "profile", "email", "offline_access"},
	}

	configBytes, err := os.ReadFile(configFilename)
	if err == nil {
		err = json.Unmarshal(configBytes, config)
		if err != nil {
			panic(err)
		}
	}

	if strings.HasPrefix(config.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(config.Key))
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	} else if config.Key == "" || !FileExists(config.Key) {
		if !initConfig && config.Key != "" {
			panic("Missing key")
		}
		rsaPrivKey, err = rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			panic(err)
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
				panic(err)
			}
		}

	} else {
		pemBytes, err := os.ReadFile(config.Key)
		if err != nil {
			panic(err)
		}
		block, _ := pem.Decode(pemBytes)
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	}

	tokenService, err = oauth2.NewTokenService(rsaPrivKey, config.Issuer, config.Scopes, config.AccessTokenLifetime)
	if err != nil {
		panic(err)
	}

	if initConfig {
		fmt.Printf("Initializing config file %s", configFilename)
		configJson, _ := json.MarshalIndent(config, "", "  ")
		err := os.WriteFile(configFilename, configJson, 0644)
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	http.HandleFunc("/", Index)
	http.Handle("/jwks", oauth2.JwksHandler(&rsaPrivKey.PublicKey))
	http.Handle("/token", oauth2.TokenHandler(tokenService, config.ClientID, config.Claims))
	http.Handle("/auth", oauth2.AuthHandler(tokenService, config.ClientID, config.Username, config.Claims))

	log.Printf("Listening on http://localhost:%d/\n", config.Port)
	err = http.ListenAndServe(fmt.Sprintf("localhost:%d", config.Port), nil)
	if err != nil {
		panic(err)
	}
}
