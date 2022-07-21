package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/directory"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/cwkr/auth-server/stringutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func IntersectScope(availableScope, requestedScope string) string {
	var results []string
	var as, rs = strings.Fields(availableScope), strings.Fields(requestedScope)
	for _, aw := range as {
		for _, rw := range rs {
			if strings.EqualFold(aw, rw) {
				results = append(results, aw)
			}
		}
	}
	return strings.Join(results, " ")
}

type authorizeHandler struct {
	tokenService   TokenCreator
	directoryStore directory.Store
	clients        Clients
	scope          string
	disablePKCE    bool
}

func (a *authorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		responseType    = strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
		clientID        = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI     = strings.TrimSpace(r.FormValue("redirect_uri"))
		state           = strings.TrimSpace(r.FormValue("state"))
		scope           = strings.TrimSpace(r.FormValue("scope"))
		challenge       = strings.TrimSpace(r.FormValue("code_challenge"))
		challengeMethod = strings.TrimSpace(r.FormValue("code_challenge_method"))
		user            User
	)

	if uid, active := a.directoryStore.IsActiveSession(r); active {
		if usr, err := a.directoryStore.Lookup(uid); err == nil {
			user = User{UserID: uid, Person: usr}
		} else {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

	if client, found := a.clients[clientID]; found && client.RedirectURIPattern != "" {
		if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
			htmlutil.Error(w, ErrorRedirectURIMismatch, http.StatusBadRequest)
			return
		}
	}

	switch responseType {
	case ResponseTypeToken:
		var x, err = a.tokenService.GenerateAccessToken(user, IntersectScope(a.scope, scope))
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
	case ResponseTypeCode:
		if !a.disablePKCE && (challenge == "" || challengeMethod != "S256") {
			htmlutil.Error(w, "code_challenge and code_challenge_method=S256 required for PKCE", http.StatusInternalServerError)
			return
		}
		var x, err = a.tokenService.GenerateAuthCode(user.UserID, clientID, IntersectScope(a.scope, scope), challenge)
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

func AuthorizeHandler(tokenService TokenCreator, directoryStore directory.Store, clients Clients, scope string, disablePKCE bool) http.Handler {
	return &authorizeHandler{
		tokenService:   tokenService,
		directoryStore: directoryStore,
		clients:        clients,
		scope:          scope,
		disablePKCE:    disablePKCE,
	}
}
