package oauth2

import (
	"fmt"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"time"
)

type TokenVerifier interface {
	VerifyAccessToken(rawToken string) (string, error)
}

func (t tokenCreator) VerifyAccessToken(rawToken string) (string, error) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", err
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID string `json:"sub"`
		Type   string `json:"typ"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s", err)
		return "", err
	}
	if tokenData.Type != TokenTypeAccessToken {
		err = fmt.Errorf("token type must be %s but was %s", TokenTypeAccessToken, tokenData.Type)
		log.Printf("!!! %s", err)
		return "", err
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", err
	} else {
		return tokenData.UserID, nil
	}
}
