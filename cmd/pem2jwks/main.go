package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/go-jose/go-jose/v3"
	"log"
	"os"
)

func main() {
	var outFilename string

	log.SetOutput(os.Stdout)

	flag.StringVar(&outFilename, "o", "", "output file")
	flag.Parse()

	var publicKeys, err = oauth2.LoadPublicKeys("./", flag.Args())
	if err != nil {
		panic(err)
	}

	var keySet = jose.JSONWebKeySet{
		Keys: oauth2.ToJwks(publicKeys),
	}

	var bytes []byte
	bytes, err = json.MarshalIndent(keySet, "", " ")
	if err != nil {
		panic(err)
	}

	if outFilename == "" {
		fmt.Print(string(bytes))
	} else {
		err := os.WriteFile(outFilename, bytes, 0644)
		if err != nil {
			panic(err)
		}
	}
}
