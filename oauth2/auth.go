package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type authHandler struct {
	tokenService TokenService
	clientID     string
	username     string
	customClaims Claims
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.Method, r.URL)

	var (
		responseType = strings.ToLower(r.FormValue("response_type"))
		clientID     = r.FormValue("client_id")
		redirectUri  = r.FormValue("redirect_uri")
		state        = r.FormValue("state")
	)

	if IsAnyEmpty(responseType, clientID, redirectUri) {
		htmlutil.Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	if clientID != a.clientID {
		htmlutil.Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	switch responseType {
	case "token":
		var x, err = a.tokenService.GenerateAccessToken(a.username, a.customClaims)
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		http.Redirect(w, r, fmt.Sprintf("%s#access_token=%s&token_type=Bearer&expires_in=%d&state=%s", redirectUri,
			url.QueryEscape(x), a.tokenService.AccessTokenLifetime(), url.QueryEscape(state)), http.StatusFound)
	case "code":
		var x, err = a.tokenService.GenerateAuthCode(a.username, a.clientID)
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		http.Redirect(w, r, fmt.Sprintf("%s#code=%s&state=%s", redirectUri,
			url.QueryEscape(x), url.QueryEscape(state)), http.StatusFound)
	default:
		htmlutil.Error(w, ErrorUnsupportedGrantType, http.StatusBadRequest)
	}
}

func AuthHandler(tokenService TokenService, clientID, username string, customClaims Claims) http.Handler {
	return &authHandler{
		tokenService: tokenService,
		clientID:     clientID,
		username:     username,
		customClaims: customClaims,
	}
}
