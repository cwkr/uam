package oauth2

import (
	"encoding/json"
	"github.com/cwkr/auth-server/oauth2/pkce"
	"github.com/cwkr/auth-server/people"
	"github.com/cwkr/auth-server/stringutil"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
)

type tokenHandler struct {
	tokenService  TokenCreator
	authenticator people.Store
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

	var clientID, clientSecret, basicAuth = r.BasicAuth()
	if !basicAuth {
		clientID = strings.TrimSpace(r.PostFormValue("client_id"))
		clientSecret = strings.TrimSpace(r.PostFormValue("client_secret"))
	}
	if client, clientExists := j.clients[clientID]; clientExists {
		if j.disablePKCE {
			if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
				Error(w, ErrorInvalidClient, "client authentication failed", http.StatusUnauthorized)
				return
			}
		}
	} else {
		Error(w, ErrorInvalidClient, "client not found", http.StatusUnauthorized)
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
			Error(w, ErrorInvalidRequest, "client_id and code parameters are required", http.StatusBadRequest)
			return
		} else if !j.disablePKCE && stringutil.IsAnyEmpty(clientID, code, codeVerifier) {
			Error(w, ErrorInvalidRequest, "client_id, code and code_verifier parameters are required", http.StatusBadRequest)
			return
		}
		var userID, scope, challenge, valid = j.tokenService.VerifyAuthCode(code)
		if !j.disablePKCE && !pkce.Verify(challenge, codeVerifier) {
			Error(w, ErrorInvalidGrant, "invalid challenge", http.StatusBadRequest)
			return
		}
		if !valid {
			Error(w, ErrorInvalidGrant, "invalid auth code", http.StatusBadRequest)
			return
		}
		var user, err = j.authenticator.Lookup(userID)
		if err != nil {
			Error(w, ErrorInternal, "user not found", http.StatusInternalServerError)
			return
		}
		accessToken, _ = j.tokenService.GenerateAccessToken(User{Person: user, UserID: userID}, scope)
		refreshToken, _ = j.tokenService.GenerateRefreshToken(userID, clientID, scope)
	case GrantTypeRefreshToken:
		if stringutil.IsAnyEmpty(clientID, refreshToken) {
			Error(w, ErrorInvalidRequest, "client_id and refresh_token parameters are required", http.StatusBadRequest)
			return
		}
		var userID, scope, valid = j.tokenService.VerifyRefreshToken(refreshToken)
		if !valid {
			Error(w, ErrorInvalidGrant, "invalid refresh_token", http.StatusBadRequest)
			return
		}
		var user, err = j.authenticator.Lookup(userID)
		if err != nil {
			Error(w, ErrorInternal, "user not found", http.StatusInternalServerError)
			return
		}
		accessToken, _ = j.tokenService.GenerateAccessToken(User{Person: user, UserID: userID}, scope)
		refreshToken = ""
	default:
		Error(w, ErrorUnsupportedGrantType, "only grant types 'authorization_code' and 'refresh_token' are supported", http.StatusBadRequest)
		return
	}

	var bytes, err = json.Marshal(TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    j.tokenService.AccessTokenLifetime(),
		RefreshToken: refreshToken,
	})
	if err != nil {
		Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func TokenHandler(tokenService TokenCreator, authenticator people.Store, clients Clients, disablePKCE bool) http.Handler {
	return &tokenHandler{
		tokenService:  tokenService,
		clients:       clients,
		disablePKCE:   disablePKCE,
		authenticator: authenticator,
	}
}
