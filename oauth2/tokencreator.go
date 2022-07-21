package oauth2

import (
	"crypto/rsa"
	"fmt"
	"github.com/cwkr/auth-server/directory"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"strings"
	"text/template"
	"time"
)

const (
	ClaimClientID       = "client_id"
	ClaimExpirationTime = "exp"
	ClaimIssuer         = "iss"
	ClaimIssuedAtTime   = "iat"
	ClaimNotBeforeTime  = "nbf"
	ClaimUserID         = "user_id"
	ClaimScope          = "scope"
	ClaimSubject        = "sub"
	ClaimType           = "typ"

	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"

	TokenTypeCode         = "code"
	TokenTypeRefreshToken = "refresh_token"
	ResponseTypeCode      = "code"
	ResponseTypeToken     = "token"
)

type Claims map[string]any

type User struct {
	directory.Person
	UserID string `json:"user_id"`
}

type TokenCreator interface {
	TokenVerifier
	GenerateAccessToken(user User, scope string) (string, error)
	GenerateAuthCode(userID, clientID, scope, challenge string) (string, error)
	GenerateRefreshToken(userID, clientID, scope string) (string, error)
	VerifyAuthCode(rawToken string) (userID, scope, challenge string, valid bool)
	VerifyRefreshToken(rawToken string) (userID, scope string, valid bool)
	AccessTokenLifetime() int64
	Issuer() string
}

type tokenCreator struct {
	privateKey           *rsa.PrivateKey
	signer               jose.Signer
	issuer               string
	scope                string
	accessTokenLifetime  int64
	refreshTokenLifetime int64
	customClaims         Claims
}

func (t tokenCreator) AccessTokenLifetime() int64 {
	return t.accessTokenLifetime
}

func (t tokenCreator) Issuer() string {
	return t.issuer
}

var customFuncs = template.FuncMap{
	"join": func(sep any, elems []string) string {
		switch sep.(type) {
		case string:
			return strings.Join(elems, sep.(string))
		case int:
			return strings.Join(elems, string(rune(sep.(int))))
		}
		return strings.Join(elems, fmt.Sprint(sep))
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
}

func customizeMap(dst, src map[string]any, data any) error {
	for key, value := range src {
		switch value.(type) {
		case string:
			var t, err = template.New(key).Funcs(customFuncs).Parse(value.(string))
			if err != nil {
				return err
			}
			var sb strings.Builder
			err = t.ExecuteTemplate(&sb, key, data)
			if err != nil {
				return err
			}
			var customValue = sb.String()
			if customValue != "" && customValue != "<no value>" {
				dst[key] = customValue
			}
		case map[string]any:
			var customValue = map[string]any{}
			if err := customizeMap(customValue, value.(map[string]any), data); err != nil {
				return err
			}
		default:
			dst[key] = value
		}
	}
	return nil
}

func (t tokenCreator) GenerateAccessToken(user User, scope string) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        user.UserID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.accessTokenLifetime,
		ClaimScope:          scope,
	}

	if err := customizeMap(claims, t.customClaims, struct {
		User
		Scope string
	}{user, scope}); err != nil {
		return "", err
	}

	return jwt.Signed(t.signer).Claims(map[string]any(claims)).CompactSerialize()
}

func (t tokenCreator) GenerateAuthCode(userID, clientID, scope, challenge string) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeCode,
		ClaimClientID:       clientID,
		ClaimUserID:         userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + 300,
		ClaimScope:          IntersectScope(t.scope, scope),
		"challenge":         challenge,
	}

	return jwt.Signed(t.signer).Claims(map[string]any(claims)).CompactSerialize()
}

func (t tokenCreator) GenerateRefreshToken(userID, clientID, scope string) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeRefreshToken,
		ClaimClientID:       clientID,
		ClaimUserID:         userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.refreshTokenLifetime,
		ClaimScope:          scope,
	}

	return jwt.Signed(t.signer).Claims(map[string]any(claims)).CompactSerialize()
}

func (t tokenCreator) VerifyAuthCode(rawToken string) (string, string, string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID    string `json:"user_id"`
		ClientID  string `json:"client_id"`
		Type      string `json:"typ"`
		Scope     string `json:"scope"`
		Challenge string `json:"challenge"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", false
	}
	if tokenData.Type != TokenTypeCode {
		return "", "", "", false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", false
	} else {
		return tokenData.UserID, tokenData.Scope, tokenData.Challenge, true
	}
}

func (t tokenCreator) VerifyRefreshToken(rawToken string) (string, string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		Type     string `json:"typ"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s", err)
		return "", "", false
	}
	if tokenData.Type != TokenTypeRefreshToken {
		return "", "", false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", false
	} else {
		return tokenData.UserID, tokenData.Scope, true
	}
}

func NewTokenService(privateKey *rsa.PrivateKey, keyID, issuer, scope string, accessTokenLifetime, refreshTokenLifetime int64, customClaims Claims) (TokenCreator, error) {
	var signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		return nil, err
	}
	return &tokenCreator{
		privateKey:           privateKey,
		signer:               signer,
		issuer:               issuer,
		scope:                scope,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		customClaims:         customClaims,
	}, nil
}
