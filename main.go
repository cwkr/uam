package main

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var rsaPrivKey *rsa.PrivateKey
var config *JwtokerConfig

func main() {
	var err error
	var configFilename string
	var showHelp bool
	var printConfig bool

	rand.Seed(time.Now().UTC().UnixNano())

	flag.StringVar(&configFilename, "config", "jwtoker.json", "config file")
	flag.BoolVar(&showHelp, "help", false, "print help and exit")
	flag.BoolVar(&printConfig, "printconfig", false, "print config and exit")
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

	configBytes, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Print(err)
	} else {
		err = json.Unmarshal(configBytes, config)
		if err != nil {
			log.Fatal(err)
		}
	}

	if config.Key == "" {
		rsaPrivKey, err = rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
	} else if strings.HasPrefix(config.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(config.Key))
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		pemBytes, err := ioutil.ReadFile(config.Key)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(pemBytes)
		rsaPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	}

	if printConfig {
		configJson, _ := json.MarshalIndent(config, "", "  ")
		fmt.Println(string(configJson))
		os.Exit(0)
	}

	http.HandleFunc("/", Index)
	http.HandleFunc("/jwks.json", Jwks)
	http.HandleFunc("/auth", Auth)
	http.HandleFunc("/favicon.ico", Favicon)

	log.Printf("Started listening on http://localhost:%d/...", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", config.Port), nil))
}
