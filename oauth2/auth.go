package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/config"
	"github.com/cwkr/auth-server/htmlutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type authHandler struct {
	tokenService TokenService
	clients      config.Clients
	username     string
	customClaims Claims
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

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

	if _, clientExists := a.clients[clientID]; !clientExists {
		htmlutil.Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	if redirectURIPattern := a.clients[clientID]; redirectURIPattern != "" {
		if !regexp.MustCompile(redirectURIPattern).MatchString(redirectUri) {
			htmlutil.Error(w, ErrorRedirectURIMismatch, http.StatusBadRequest)
			return
		}
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
		var x, err = a.tokenService.GenerateAuthCode(a.username, clientID)
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

func AuthHandler(tokenService TokenService, cfg *config.Config) http.Handler {
	return &authHandler{
		tokenService: tokenService,
		clients:      cfg.Clients,
		username:     cfg.Username,
		customClaims: cfg.Claims,
	}
}
