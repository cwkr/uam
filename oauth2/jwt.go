package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/cwkr/auth-server/oauth2/pkce"
	"github.com/cwkr/auth-server/store"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"log"
	"net/http"
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
	ClaimPrincipal      = "prn"
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

type Claims map[string]interface{}

type User struct {
	store.User
	UserID string
}

type TokenService interface {
	GenerateAccessToken(user User) (string, error)
	GenerateAuthCode(userID, clientID, challenge string) (string, error)
	GenerateRefreshToken(userID, clientID string) (string, error)
	VerifyAuthCode(rawToken string) (userID, challenge string, valid bool)
	VerifyRefreshToken(rawToken string) (userID string, valid bool)
	AccessTokenLifetime() int64
	RefreshTokenLifetime() int64
	Issuer() string
}

type tokenService struct {
	privateKey           *rsa.PrivateKey
	signer               jose.Signer
	issuer               string
	scopes               []string
	accessTokenLifetime  int64
	refreshTokenLifetime int64
	customClaims         Claims
}

func (t tokenService) AccessTokenLifetime() int64 {
	return t.accessTokenLifetime
}

func (t tokenService) RefreshTokenLifetime() int64 {
	return t.refreshTokenLifetime
}

func (t tokenService) Issuer() string {
	return t.issuer
}

func (t tokenService) GenerateAccessToken(user User) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        user.UserID,
		ClaimPrincipal:      user.UserID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.accessTokenLifetime,
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	var customFuncs = template.FuncMap{
		"join": func(sep interface{}, elems []string) string {
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

	for key, value := range t.customClaims {
		switch value.(type) {
		case string:
			var t, err = template.New(key).Funcs(customFuncs).Parse(value.(string))
			if err != nil {
				return "", err
			}
			var sb strings.Builder
			err = t.ExecuteTemplate(&sb, key, user)
			if err != nil {
				return "", err
			}
			var customValue = sb.String()
			if customValue != "" {
				claims[key] = customValue
			}
		default:
			claims[key] = value
		}
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t tokenService) GenerateAuthCode(userID, clientID, challenge string) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeCode,
		ClaimClientID:       clientID,
		ClaimPrincipal:      userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + 300,
		ClaimScope:          strings.Join(t.scopes, " "),
		"challenge":         challenge,
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t tokenService) GenerateRefreshToken(userID, clientID string) (string, error) {
	var now = time.Now().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimType:           TokenTypeRefreshToken,
		ClaimClientID:       clientID,
		ClaimPrincipal:      userID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + t.refreshTokenLifetime,
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t tokenService) VerifyAuthCode(rawToken string) (string, string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return "", "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID    string `json:"prn"`
		ClientID  string `json:"client_id"`
		Type      string `json:"typ"`
		Challenge string `json:"challenge"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s\n", err)
		return "", "", false
	}
	if tokenData.Type != TokenTypeCode {
		return "", "", false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return "", "", false
	} else {
		return tokenData.UserID, tokenData.Challenge, true
	}
}

func (t tokenService) VerifyRefreshToken(rawToken string) (string, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return "", false
	}
	var claims = jwt.Claims{}
	var tokenData = struct {
		UserID   string `json:"prn"`
		ClientID string `json:"client_id"`
		Type     string `json:"typ"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &tokenData); err != nil {
		log.Printf("!!! %s\n", err)
		return "", false
	}
	if tokenData.Type != TokenTypeRefreshToken {
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
		return tokenData.UserID, true
	}
}

func NewTokenService(privateKey *rsa.PrivateKey, keyID, issuer string, scopes []string, accessTokenLifetime, refreshTokenLifetime int64, customClaims Claims) (TokenService, error) {
	var signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		return nil, err
	}
	return &tokenService{
		privateKey:           privateKey,
		signer:               signer,
		issuer:               issuer,
		scopes:               scopes,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		customClaims:         customClaims,
	}, nil
}

type tokenHandler struct {
	tokenService  TokenService
	authenticator store.Authenticator
	clients       Clients
	disablePKCE   bool
}

func (j *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "OPTIONS, POST")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var clientID, _, basicAuth = r.BasicAuth()
	if !basicAuth {
		clientID = strings.TrimSpace(r.PostFormValue("client_id"))
	}
	if _, clientExists := j.clients[clientID]; !clientExists {
		Error(w, ErrorInvalidClient, "wrong client id")
		return
	}
	var (
		grantType    = strings.ToLower(strings.TrimSpace(r.PostFormValue("grant_type")))
		code         = strings.TrimSpace(r.PostFormValue("code"))
		refreshToken = strings.TrimSpace(r.PostFormValue("refresh_token"))
		codeVerifier = strings.TrimSpace(r.PostFormValue("code_verifier"))
		accessToken  string
	)

	switch grantType {
	case GrantTypeAuthorizationCode:
		if j.disablePKCE && stringutil.IsAnyEmpty(clientID, code) {
			Error(w, ErrorInvalidRequest, "client_id and code parameters are required")
			return
		} else if !j.disablePKCE && stringutil.IsAnyEmpty(clientID, code, codeVerifier) {
			Error(w, ErrorInvalidRequest, "client_id, code and code_verifier parameters are required")
			return
		}
		var userID, challenge, valid = j.tokenService.VerifyAuthCode(code)
		if !j.disablePKCE && !pkce.Verify(challenge, codeVerifier) {
			Error(w, ErrorInvalidGrant, "invalid challenge")
			return
		}
		if !valid {
			Error(w, ErrorInvalidGrant, "invalid auth code")
			return
		}
		var user, found = j.authenticator.Lookup(userID)
		if !found {
			Error(w, ErrorInvalidGrant, "user not found")
			return
		}
		accessToken, _ = j.tokenService.GenerateAccessToken(User{User: user, UserID: userID})
		refreshToken, _ = j.tokenService.GenerateRefreshToken(userID, clientID)
	case GrantTypeRefreshToken:
		if stringutil.IsAnyEmpty(clientID, refreshToken) {
			Error(w, ErrorInvalidRequest, "client_id and refresh_token parameters are required")
			return
		}
		var userID, valid = j.tokenService.VerifyRefreshToken(refreshToken)
		if !valid {
			Error(w, ErrorInvalidGrant, "invalid refresh_token")
			return
		}
		var user, found = j.authenticator.Lookup(userID)
		if !found {
			Error(w, ErrorInvalidGrant, "user not found")
			return
		}
		accessToken, _ = j.tokenService.GenerateAccessToken(User{User: user, UserID: userID})
		refreshToken = ""
	default:
		Error(w, ErrorUnsupportedGrantType, "only grant types 'authorization_code' and 'refresh_token' are supported")
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

func TokenHandler(tokenService TokenService, authenticator store.Authenticator, clients Clients, disablePKCE bool) http.Handler {
	return &tokenHandler{
		tokenService:  tokenService,
		clients:       clients,
		disablePKCE:   disablePKCE,
		authenticator: authenticator,
	}
}
