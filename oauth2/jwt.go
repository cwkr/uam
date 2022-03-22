package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/cwkr/auth-server/config"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	ClaimClientID       = "client_id"
	ClaimExpirationTime = "exp"
	ClaimIssuer         = "iss"
	ClaimIssuedAtTime   = "iat"
	ClaimNotBeforeTime  = "nbf"
	ClaimPrincipal      = "prn"
	ClaimScope          = "scope"
	ClaimSubject        = "sub"

	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

type Claims map[string]interface{}

type TokenService interface {
	GenerateAccessToken(username string, customClaims Claims) (string, error)
	GenerateAuthCode(username, clientID string) (string, error)
	GenerateRefreshToken(username, clientID string) (string, error)
	VerifyToken(rawToken string) (username string, valid bool)
	AccessTokenLifetime() int
}

type tokenService struct {
	privateKey          *rsa.PrivateKey
	signer              jose.Signer
	issuer              string
	scopes              []string
	accessTokenLifetime int
}

func (t *tokenService) AccessTokenLifetime() int {
	return t.accessTokenLifetime
}

func (t *tokenService) GenerateAccessToken(username string, customClaims Claims) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        username,
		ClaimPrincipal:      username,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + int64(t.accessTokenLifetime),
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	for key, value := range customClaims {
		claims[key] = value
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t *tokenService) GenerateAuthCode(username, clientID string) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        username,
		ClaimClientID:       clientID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + 300,
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t *tokenService) GenerateRefreshToken(username, clientID string) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        username,
		ClaimClientID:       clientID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + int64(t.accessTokenLifetime*10),
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t *tokenService) VerifyToken(rawToken string) (username string, valid bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return "", false
	}
	var claims = jwt.Claims{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims); err != nil {
		log.Printf("!!! %s\n", err)
		return "", false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return "", false
	} else {
		return claims.Subject, true
	}
}

func NewTokenService(privateKey *rsa.PrivateKey, issuer string, scopes []string, accessTokenLifetime int) (TokenService, error) {
	var signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		return nil, err
	}
	return &tokenService{
		privateKey:          privateKey,
		signer:              signer,
		issuer:              issuer,
		scopes:              scopes,
		accessTokenLifetime: accessTokenLifetime,
	}, nil
}

type tokenHandler struct {
	tokenService TokenService
	clients      config.Clients
	customClaims Claims
}

func (j *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var clientID, _, basicAuth = r.BasicAuth()
	if !basicAuth {
		clientID = r.PostFormValue("client_id")
	}
	if _, clientExists := j.clients[clientID]; !clientExists {
		Error(w, ErrorInvalidClient, "Wrong client id")
		return
	}
	var (
		grantType    = strings.ToLower(r.PostFormValue("grant_type"))
		code         = r.PostFormValue("code")
		refreshToken = r.PostFormValue("refresh_token")
		accessToken  string
	)

	switch grantType {
	case GrantTypeAuthorizationCode:
		if IsAnyEmpty(clientID, code) {
			Error(w, ErrorInvalidRequest, "Code and client id is required")
			return
		}
		var username, valid = j.tokenService.VerifyToken(code)
		if valid {
			accessToken, _ = j.tokenService.GenerateAccessToken(username, j.customClaims)
			refreshToken, _ = j.tokenService.GenerateRefreshToken(username, clientID)
		} else {
			Error(w, ErrorInvalidGrant, "Invalid auth code")
			return
		}
	case GrantTypeRefreshToken:
		if IsAnyEmpty(clientID, refreshToken) {
			Error(w, ErrorInvalidRequest, "Refresh token and client id is required")
			return
		}
		var username, valid = j.tokenService.VerifyToken(refreshToken)
		if valid {
			accessToken, _ = j.tokenService.GenerateAccessToken(username, j.customClaims)
			refreshToken = ""
		} else {
			Error(w, ErrorInvalidGrant, "Invalid auth code")
			return
		}
	default:
		Error(w, ErrorUnsupportedGrantType, "Only grant types 'authorization_code' and 'refresh_token' are supported")
		return
	}

	var bytes, err = json.Marshal(TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    j.tokenService.AccessTokenLifetime(),
		RefreshToken: refreshToken,
	})
	if err != nil {
		Error(w, ErrorInternal, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func TokenHandler(tokenService TokenService, cfg *config.Config) http.Handler {
	return &tokenHandler{
		tokenService: tokenService,
		clients:      cfg.Clients,
		customClaims: cfg.Claims,
	}
}
