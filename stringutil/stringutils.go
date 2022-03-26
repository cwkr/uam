package stringutil

import (
	"crypto/rand"
	"encoding/base64"
	"math"
	"math/big"
)

func IsAnyEmpty(strings ...string) bool {
	for _, s := range strings {
		if s == "" {
			return true
		}
	}
	return false
}

func RandomBytesString(max int) string {
	var bytes []byte = make([]byte, 0, max)
	for i := 0; i < max; i++ {
		nBig, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint8))
		if err != nil {
			panic(err)
		}
		bytes = append(bytes, byte(nBig.Int64()))
	}

	return base64.URLEncoding.EncodeToString(bytes)
}
