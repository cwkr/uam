package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/oklog/ulid/v2"
	"strings"
	"time"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypePassword          = "password"

	TokenTypeCode         = "code"
	TokenTypeRefreshToken = "refresh_token"
	ResponseTypeCode      = "code"
	ResponseTypeToken     = "token"
)

var ErrInvalidTokenType = errors.New("invalid token type (typ)")

type User struct {
	people.Person
	UserID string `json:"user_id"`
}

type VerifiedClaims struct {
	UserID    string           `json:"user_id"`
	ClientID  string           `json:"client_id"`
	TokenID   string           `json:"jti"`
	Type      string           `json:"typ"`
	Scope     string           `json:"scope"`
	Challenge string           `json:"challenge"`
	Nonce     string           `json:"nonce"`
	Expiry    *jwt.NumericDate `json:"exp"`
}

func NewTokenID(timestamp time.Time) string {
	id, _ := ulid.New(ulid.Timestamp(timestamp), rand.Reader)
	return id.String()
}

type TokenCreator interface {
	GenerateAccessToken(user User, subject, clientID, scope string) (string, error)
	GenerateIDToken(user User, clientID, scope, accessTokenHash, nonce string) (string, error)
	GenerateAuthCode(userID, clientID, scope, challenge, nonce string) (string, error)
	GenerateRefreshToken(userID, clientID, scope, nonce string) (string, error)
	Verify(rawToken, tokenType string) (*VerifiedClaims, error)
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

func (t tokenCreator) GenerateAccessToken(user User, subject, clientID, scope string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       subject,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + t.accessTokenTTL,
		ClaimAudience:      []string{t.issuer, clientID},
		ClaimTokenID:       NewTokenID(now),
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}

	AddExtraClaims(claims, t.accessTokenExtraClaims, user, clientID)

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) GenerateIDToken(user User, clientID, scope, accessTokenHash, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:          t.issuer,
		ClaimSubject:         user.UserID,
		ClaimIssuedAtTime:    now.Unix(),
		ClaimNotBeforeTime:   now.Unix(),
		ClaimExpiryTime:      now.Unix() + t.idTokenTTL,
		ClaimAudience:        []string{t.issuer, clientID},
		ClaimAccessTokenHash: accessTokenHash,
		ClaimNonce:           nonce,
		ClaimTokenID:         NewTokenID(now),
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
	AddExtraClaims(claims, t.idTokenExtraClaims, user, clientID)

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) GenerateAuthCode(userID, clientID, scope, challenge, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       NewTokenID(now),
		ClaimType:          TokenTypeCode,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + 300,
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
	var now = time.Now()
	var tokenID = NewTokenID(now)

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       tokenID,
		ClaimType:          TokenTypeRefreshToken,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + t.refreshTokenTTL,
		ClaimTokenID:       tokenID,
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return jwt.Signed(t.signer).Claims(claims).CompactSerialize()
}

func (t tokenCreator) Verify(rawToken, tokenType string) (*VerifiedClaims, error) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, err
	}
	var claims = jwt.Claims{}
	var verifiedClaims = VerifiedClaims{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &verifiedClaims); err != nil {
		return nil, err
	}
	if tokenType != "" && verifiedClaims.Type != tokenType {
		return nil, ErrInvalidTokenType
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		return nil, err
	} else {
		return &verifiedClaims, nil
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
