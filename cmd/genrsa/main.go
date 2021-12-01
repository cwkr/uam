package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var (
		outFilename string
		keySize       int
		rsaPrivateKey *rsa.PrivateKey
		err           error
	)

	log.SetOutput(os.Stdout)

	flag.StringVar(&outFilename, "out", "", "output file")
	flag.IntVar(&keySize, "size", 2048, "key size")
	flag.Parse()

	if keySize < 512 {
		panic("key size less than 512")
	}

	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}

	pubASN1 := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pubASN1,
	})
	if outFilename == "" {
		fmt.Print(string(keyBytes))
	} else {
		err := os.WriteFile(outFilename, keyBytes, 0600)
		if err != nil {
			panic(err)
		}
	}
}
