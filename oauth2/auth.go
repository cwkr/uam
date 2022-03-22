package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/config"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type Authenticator interface {
	Authenticate(userID, password string) (map[string]interface{}, bool)
	Lookup(userID string) (map[string]interface{}, bool)
}

type authHandler struct {
	tokenService  TokenService
	config        *config.Config
	authenticator Authenticator
	sessionStore  sessions.Store
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var session, _ = a.sessionStore.Get(r, a.config.SessionID)

	var (
		responseType = strings.ToLower(r.FormValue("response_type"))
		clientID     = r.FormValue("client_id")
		redirectURI  = r.FormValue("redirect_uri")
		state        = r.FormValue("state")
		userID       string
	)

	if uid := session.Values["user_id"]; uid != nil {
		userID = uid.(string)
	}

	if userID == "" {
		httputil.RedirectQuery(w, r, strings.TrimRight(a.config.Issuer, "/")+"/login", r.URL.Query())
		return
	}

	if IsAnyEmpty(responseType, clientID, redirectURI) {
		htmlutil.Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	if _, clientExists := a.config.Clients[clientID]; !clientExists {
		htmlutil.Error(w, ErrorInvalidClient, http.StatusForbidden)
		return
	}

	if redirectURIPattern := a.config.Clients[clientID]; redirectURIPattern != "" {
		if !regexp.MustCompile(redirectURIPattern).MatchString(redirectURI) {
			htmlutil.Error(w, ErrorRedirectURIMismatch, http.StatusBadRequest)
			return
		}
	}

	switch responseType {
	case "token":
		var x, err = a.tokenService.GenerateAccessToken(userID, a.config.Claims)
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		httputil.RedirectFragment(w, r, redirectURI, url.Values{
			"access_token": {x},
			"token_type":   {"Bearer"},
			"expires_in":   {fmt.Sprint(a.tokenService.AccessTokenLifetime())},
			"state":        {state},
		})
	case "code":
		var x, err = a.tokenService.GenerateAuthCode(userID, clientID)
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		httputil.RedirectQuery(w, r, redirectURI, url.Values{"code": {x}, "state": {state}})
	default:
		htmlutil.Error(w, ErrorUnsupportedGrantType, http.StatusBadRequest)
	}
}

func AuthHandler(tokenService TokenService, cfg *config.Config, sessionStore sessions.Store) http.Handler {
	return &authHandler{
		tokenService:  tokenService,
		config:        cfg,
		authenticator: cfg,
		sessionStore:  sessionStore,
	}
}
