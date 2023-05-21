package oauth2

import (
	"crypto/rsa"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"strings"
	"time"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypePassword          = "password"

	TokenTypeCode         = "code"
	TokenTypeRefreshToken = "refresh"
	TokenTypeAccessToken  = "at"
	TokenTypeIDToken      = "id"
	ResponseTypeCode      = "code"
	ResponseTypeToken     = "token"
)

type User struct {
	people.Person
	UserID string `json:"user_id"`
}

type TokenCreator interface {
	GenerateAccessToken(user User, clientID, scope string) (string, error)
	GenerateIDToken(user User, clientID, scope, accessTokenHash, nonce string) (string, error)
	GenerateAuthCode(userID, clientID, scope, challenge, nonce string) (string, error)
	GenerateRefreshToken(userID, clientID, scope, nonce string) (string, error)
	VerifyAuthCode(rawToken string) (userID, scope, challenge, nonce string, valid bool)
	VerifyRefreshToken(rawToken string) (userID, scope, nonce string, valid bool)
	AccessTokenTTL() int64
	Issuer() string
}

type tokenCreator struct {
	privateKey             *rsa.PrivateKey
	signer                 jose.Signer
	issuer                 string
	scope                  string
	accessTokenTTL         int64
	refreshTokenTTL        int64
	idTokenTTL             int64
	accessTokenExtraClaims map[string]string
	idTokenExtraClaims     map[string]string
}

func (t tokenCreator) AccessTokenTTL() int64 {
	return t.accessTokenTTL
}

func (t tokenCreator) Issuer() string {
	return t.issuer
}

func (t tokenCreator) GenerateAccessToken(user User, clientID, scope string) (string, error) {
	var now = time.Now().Unix()

	var claims = map[string]any{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        user.UserID,
		ClaimType:           TokenTypeAccessToken,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.accessTokenTTL,
		ClaimAudience:       []string{t.issuer, clientID},
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}

	AddExtraClaims(claims, t.accessTokenExtraClaims, user)

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) GenerateIDToken(user User, clientID, scope, accessTokenHash, nonce string) (string, error) {
	var now = time.Now().Unix()

	var claims = map[string]any{
		ClaimIssuer:          t.issuer,
		ClaimSubject:         user.UserID,
		ClaimType:            TokenTypeIDToken,
		ClaimIssuedAtTime:    now,
		ClaimNotBeforeTime:   now,
		ClaimExpirationTime:  now + t.idTokenTTL,
		ClaimAudience:        []string{t.issuer, clientID},
		ClaimAccessTokenHash: accessTokenHash,
		ClaimNonce:           nonce,
	}

	if strings.Contains(scope, "profile") {
		AddProfileClaims(claims, user)
	}
	if strings.Contains(scope, "email") {
		AddEmailClaims(claims, user)
	}
	if strings.Contains(scope, "phone") {
		AddPhoneClaims(claims, user)
	}
	if strings.Contains(scope, "address") {
		AddAddressClaims(claims, user)
	}
	AddExtraClaims(claims, t.idTokenExtraClaims, user)

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) GenerateAuthCode(userID, clientID, scope, challenge, nonce string) (string, error) {
	var now = time.Now().Unix()

	var claims = map[string]any{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeCode,
		ClaimClientID:       clientID,
		ClaimUserID:         userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + 300,
	}

	if scope != "" {
		claims[ClaimScope] = IntersectScope(t.scope, scope)
	}
	if challenge != "" {
		claims["challenge"] = challenge
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) GenerateRefreshToken(userID, clientID, scope, nonce string) (string, error) {
	var now = time.Now().Unix()

	var claims = map[string]any{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeRefreshToken,
		ClaimClientID:       clientID,
		ClaimUserID:         userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.refreshTokenTTL,
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) VerifyAuthCode(rawToken string) (string, string, string, string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID    string `json:"user_id"`
		ClientID  string `json:"client_id"`
		Type      string `json:"typ"`
		Scope     string `json:"scope"`
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", "", false
	}
	if tokenData.Type != TokenTypeCode {
		return "", "", "", "", false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", "", false
	} else {
		return tokenData.UserID, tokenData.Scope, tokenData.Challenge, tokenData.Nonce, true
	}
}

func (t tokenCreator) VerifyRefreshToken(rawToken string) (string, string, string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		Type     string `json:"typ"`
		Nonce    string `json:"nonce"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s", err)
		return "", "", "", false
	}
	if tokenData.Type != TokenTypeRefreshToken {
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
		return tokenData.UserID, tokenData.Scope, tokenData.Nonce, true
	}
}

func NewTokenCreator(privateKey *rsa.PrivateKey, keyID, issuer, scope string,
	accessTokenTTL, refreshTokenTTL, idTokenTTL int64,
	accessTokenExtraClaims, idTokenExtraClaims map[string]string) (TokenCreator, error) {
	var signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		return nil, err
	}
	return &tokenCreator{
		privateKey:             privateKey,
		signer:                 signer,
		issuer:                 issuer,
		scope:                  scope,
		accessTokenTTL:         accessTokenTTL,
		refreshTokenTTL:        refreshTokenTTL,
		idTokenTTL:             idTokenTTL,
		accessTokenExtraClaims: accessTokenExtraClaims,
		idTokenExtraClaims:     idTokenExtraClaims,
	}, nil
}
