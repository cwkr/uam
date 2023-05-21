package oauth2

import (
	"errors"
	"github.com/cwkr/auth-server/internal/maputil"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"strings"
	"time"
)

var (
	ErrMissingKid          = errors.New("missing key id")
	ErrMatchingKeyNotFound = errors.New("matching key not found")
)

type TokenVerifier interface {
	VerifyToken(rawToken string) (string, error)
}

type tokenVerifier struct {
	publicKeys map[string]any
}

func NewTokenVerifier(publicKeys map[string]any) TokenVerifier {
	return &tokenVerifier{publicKeys: maputil.LowerKeys(publicKeys)}
}

func (t tokenVerifier) VerifyToken(rawToken string) (string, error) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", err
	}
	if len(token.Headers) == 0 || token.Headers[0].KeyID == "" {
		return "", ErrMissingKid
	}
	var publicKey, found = t.publicKeys[strings.ToLower(token.Headers[0].KeyID)]
	if !found {
		return "", ErrMatchingKeyNotFound
	}
	var claims = jwt.Claims{}
	if err := token.Claims(publicKey, &claims); err != nil {
		log.Printf("!!! %s", err)
		return "", err
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", err
	} else {
		return claims.Subject, nil
	}
}
