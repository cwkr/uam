package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/cwkr/auth-server/userstore"
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
	ClaimUserID         = "user_id"

	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

type Claims map[string]interface{}

type User struct {
	userstore.User
	UserID string
}

type TokenService interface {
	GenerateAccessToken(user User) (string, error)
	GenerateAuthCode(user User, clientID string) (string, error)
	GenerateRefreshToken(user User, clientID string) (string, error)
	VerifyToken(rawToken string) (user User, valid bool)
	AccessTokenLifetime() int
	Issuer() string
}

type tokenService struct {
	privateKey          *rsa.PrivateKey
	signer              jose.Signer
	issuer              string
	scopes              []string
	accessTokenLifetime int
	customClaims        Claims
}

func (t tokenService) AccessTokenLifetime() int {
	return t.accessTokenLifetime
}

func (t tokenService) Issuer() string {
	return t.issuer
}

func (t tokenService) GenerateAccessToken(user User) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        user.UserID,
		ClaimPrincipal:      user.UserID,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + int64(t.accessTokenLifetime),
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

func (t tokenService) GenerateAuthCode(user User, clientID string) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimClientID:       clientID,
		ClaimUserID:         user.UserID,
		"user":              user.User,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + 300,
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t tokenService) GenerateRefreshToken(user User, clientID string) (string, error) {
	var now = time.Now().UTC().Unix()

	var claims = Claims{
		ClaimIssuer:         t.issuer,
		ClaimSubject:        stringutil.RandomBytesString(16),
		ClaimClientID:       clientID,
		ClaimUserID:         user.UserID,
		"user":              user.User,
		ClaimIssuedAtTime:   now,
		ClaimNotBeforeTime:  now,
		ClaimExpirationTime: now + int64(t.accessTokenLifetime*10),
		ClaimScope:          strings.Join(t.scopes, " "),
	}

	return jwt.Signed(t.signer).Claims(map[string]interface{}(claims)).CompactSerialize()
}

func (t tokenService) VerifyToken(rawToken string) (User, bool) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return User{}, false
	}
	var claims = jwt.Claims{}
	var userData = struct {
		UserID string         `json:"user_id"`
		User   userstore.User `json:"user"`
	}{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &userData); err != nil {
		log.Printf("!!! %s\n", err)
		return User{}, false
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		log.Printf("!!! %s\n", err)
		return User{}, false
	} else {
		return User{UserID: userData.UserID, User: userData.User}, true
	}
}

func NewTokenService(privateKey *rsa.PrivateKey, issuer string, scopes []string, accessTokenLifetime int, customClaims Claims) (TokenService, error) {
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
		customClaims:        customClaims,
	}, nil
}

type tokenHandler struct {
	tokenService TokenService
	clients      Clients
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
		if stringutil.IsAnyEmpty(clientID, code) {
			Error(w, ErrorInvalidRequest, "Code and client id is required")
			return
		}
		var user, valid = j.tokenService.VerifyToken(code)
		if valid {
			accessToken, _ = j.tokenService.GenerateAccessToken(user)
			refreshToken, _ = j.tokenService.GenerateRefreshToken(user, clientID)
		} else {
			Error(w, ErrorInvalidGrant, "Invalid auth code")
			return
		}
	case GrantTypeRefreshToken:
		if stringutil.IsAnyEmpty(clientID, refreshToken) {
			Error(w, ErrorInvalidRequest, "Refresh token and client id is required")
			return
		}
		var user, valid = j.tokenService.VerifyToken(refreshToken)
		if valid {
			accessToken, _ = j.tokenService.GenerateAccessToken(user)
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

func TokenHandler(tokenService TokenService, clients Clients) http.Handler {
	return &tokenHandler{
		tokenService: tokenService,
		clients:      clients,
	}
}
