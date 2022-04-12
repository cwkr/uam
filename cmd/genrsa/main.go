package main

import (
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/oauth2"
	"log"
	"os"
)

func main() {
	var (
		outFilename string
		keySize     int
		err         error
		keyBytes    []byte
	)

	log.SetOutput(os.Stdout)

	flag.StringVar(&outFilename, "o", "", "output file")
	flag.IntVar(&keySize, "size", 2048, "key size")
	flag.Parse()

	if keySize < 512 {
		panic("key size less than 512")
	}

	_, keyBytes, err = oauth2.GeneratePrivateKey(keySize)
	if err != nil {
		panic(err)
	}

	if outFilename == "" {
		fmt.Print(string(keyBytes))
	} else {
		err := os.WriteFile(outFilename, keyBytes, 0600)
		if err != nil {
			panic(err)
		}
	}
}
