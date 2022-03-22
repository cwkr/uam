package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/config"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	rsaPrivKey   *rsa.PrivateKey
	cfg          *config.Config
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

	flag.StringVar(&configFilename, "config", "auth-server.json", "config file")
	flag.BoolVar(&showHelp, "help", false, "print help and exit")
	flag.BoolVar(&initConfig, "init", false, "init config and exit")
	flag.Parse()

	if showHelp {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set defaults
	cfg = &config.Config{
		Issuer:              "http://localhost:1337/",
		Port:                1337,
		Username:            "user",
		Clients:             config.Clients{"app": "https?:\\/\\/localhost(:\\d+)?\\/"},
		AccessTokenLifetime: 3600,
		Claims:              map[string]interface{}{"email": "user@example.org"},
		Scopes:              []string{"profile", "email", "offline_access"},
	}

	configBytes, err := os.ReadFile(configFilename)
	if err == nil {
		err = json.Unmarshal(configBytes, cfg)
		if err != nil {
			panic(err)
		}
	}

	if strings.HasPrefix(cfg.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(cfg.Key))
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	} else if cfg.Key == "" || !FileExists(cfg.Key) {
		if !initConfig && cfg.Key != "" {
			panic("Missing key")
		}
		rsaPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		pubASN1 := x509.MarshalPKCS1PrivateKey(rsaPrivKey)
		keyBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pubASN1,
		})
		if cfg.Key == "" {
			cfg.Key = string(keyBytes)
		} else {
			err := os.WriteFile(cfg.Key, keyBytes, 0600)
			if err != nil {
				panic(err)
			}
		}

	} else {
		pemBytes, err := os.ReadFile(cfg.Key)
		if err != nil {
			panic(err)
		}
		block, _ := pem.Decode(pemBytes)
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	}

	tokenService, err = oauth2.NewTokenService(rsaPrivKey, cfg.Issuer, cfg.Scopes, cfg.AccessTokenLifetime)
	if err != nil {
		panic(err)
	}

	if initConfig {
		log.Printf("Initializing config file %s", configFilename)
		configJson, _ := json.MarshalIndent(cfg, "", "  ")
		err := os.WriteFile(configFilename, configJson, 0644)
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler()
	router.HandleFunc("/", Index).Methods(http.MethodGet)
	router.Handle("/jwks", oauth2.JwksHandler(&rsaPrivKey.PublicKey)).Methods(http.MethodGet)
	router.Handle("/token", oauth2.TokenHandler(tokenService, cfg)).Methods(http.MethodPost)
	router.Handle("/auth", oauth2.AuthHandler(tokenService, cfg)).Methods(http.MethodGet)

	log.Printf("Listening on http://localhost:%d/", cfg.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), router)
	if err != nil {
		panic(err)
	}
}
