package oauth2

import (
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
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
	tokenService TokenCreator
	peopleStore  people.Store
	clients      Clients
	scope        string
	disablePKCE  bool
}

func (a *authorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		timing          = httputil.NewTiming()
		responseType    = strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
		clientID        = strings.ToLower(strings.TrimSpace(r.FormValue("client_id")))
		redirectURI     = strings.TrimSpace(r.FormValue("redirect_uri"))
		state           = strings.TrimSpace(r.FormValue("state"))
		scope           = strings.TrimSpace(r.FormValue("scope"))
		challenge       = strings.TrimSpace(r.FormValue("code_challenge"))
		challengeMethod = strings.TrimSpace(r.FormValue("code_challenge_method"))
		nonce           = strings.TrimSpace(r.FormValue("nonce"))
		user            User
	)

	if uid, active := a.peopleStore.IsActiveSession(r); active {
		timing.Start("store")
		if person, err := a.peopleStore.Lookup(uid); err == nil {
			user = User{UserID: uid, Person: *person}
		} else {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("store")
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
		timing.Start("jwtgen")
		var x, err = a.tokenService.GenerateAccessToken(user, IntersectScope(a.scope, scope))
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("jwtgen")

		httputil.NoCache(w)
		timing.Report(w)
		httputil.RedirectFragment(w, r, redirectURI, url.Values{
			"access_token": {x},
			"token_type":   {"Bearer"},
			"expires_in":   {fmt.Sprint(a.tokenService.AccessTokenTTL())},
			"state":        {state},
		})
	case ResponseTypeCode:
		if !a.disablePKCE && (challenge == "" || challengeMethod != "S256") {
			htmlutil.Error(w, "code_challenge and code_challenge_method=S256 required for PKCE", http.StatusInternalServerError)
			return
		}
		timing.Start("jwtgen")
		var x, err = a.tokenService.GenerateAuthCode(user.UserID, clientID, IntersectScope(a.scope, scope), challenge, nonce)
		if err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("jwtgen")

		httputil.NoCache(w)
		timing.Report(w)
		httputil.RedirectQuery(w, r, redirectURI, url.Values{"code": {x}, "state": {state}})
	default:
		htmlutil.Error(w, ErrorUnsupportedGrantType, http.StatusBadRequest)
	}
}

func AuthorizeHandler(tokenService TokenCreator, peopleStore people.Store, clients Clients, scope string, disablePKCE bool) http.Handler {
	return &authorizeHandler{
		tokenService: tokenService,
		peopleStore:  peopleStore,
		clients:      clients,
		scope:        scope,
		disablePKCE:  disablePKCE,
	}
}