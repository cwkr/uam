package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/cwkr/auth-server/userstore"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type authHandler struct {
	tokenService  TokenService
	authenticator userstore.Authenticator
	sessionStore  sessions.Store
	sessionID     string
	clients       Clients
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var session, _ = a.sessionStore.Get(r, a.sessionID)

	var (
		responseType = strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
		clientID     = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI  = strings.TrimSpace(r.FormValue("redirect_uri"))
		state        = strings.TrimSpace(r.FormValue("state"))
		user         User
	)

	if usr, uid := session.Values["user"], session.Values["user_id"]; usr != nil && uid != nil {
		user = User{UserID: uid.(string), User: usr.(userstore.User)}
	} else {
		httputil.RedirectQuery(w, r, strings.TrimRight(a.tokenService.Issuer(), "/")+"/login", r.URL.Query())
		return
	}

	if stringutil.IsAnyEmpty(responseType, clientID, redirectURI) {
		htmlutil.Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	if _, clientExists := a.clients[clientID]; !clientExists {
		htmlutil.Error(w, ErrorInvalidClient, http.StatusForbidden)
		return
	}

	if redirectURIPattern := a.clients[clientID]; redirectURIPattern != "" {
		if !regexp.MustCompile(redirectURIPattern).MatchString(redirectURI) {
			htmlutil.Error(w, ErrorRedirectURIMismatch, http.StatusBadRequest)
			return
		}
	}

	switch responseType {
	case "token":
		var x, err = a.tokenService.GenerateAccessToken(user)
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
		var x, err = a.tokenService.GenerateAuthCode(user, clientID)
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

func AuthHandler(tokenService TokenService, authenticator userstore.Authenticator, clients Clients, sessionStore sessions.Store, sessionID string) http.Handler {
	return &authHandler{
		tokenService:  tokenService,
		authenticator: authenticator,
		clients:       clients,
		sessionStore:  sessionStore,
		sessionID:     sessionID,
	}
}
