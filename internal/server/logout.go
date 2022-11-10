package server

import (
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type logoutHandler struct {
	basePath     string
	settings     *Settings
	sessionStore sessions.Store
	clients      oauth2.Clients
}

func (l *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		session, _  = l.sessionStore.Get(r, l.settings.SessionName)
		clientID    = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI = strings.TrimSpace(r.FormValue("post_logout_redirect_uri"))
		idTokenHint = strings.TrimSpace(r.FormValue("id_token_hint"))
	)

	if idTokenHint != "" {
		if token, err := jwt.ParseSigned(idTokenHint); err == nil {
			var claims = jwt.Claims{}
			if err := token.UnsafeClaimsWithoutVerification(&claims); err == nil {
				if len([]string(claims.Audience)) > 1 && claims.Issuer == l.settings.Issuer {
					clientID = claims.Audience[1]
				}
			}
		}
	}

	if clientID == "" {
		htmlutil.Error(w, l.basePath, "client_id or id_token_hint parameters are required", http.StatusBadRequest)
		return
	}

	if _, clientExists := l.clients[strings.ToLower(clientID)]; !clientExists {
		htmlutil.Error(w, l.basePath, "invalid_client", http.StatusForbidden)
		return
	}

	if redirectURI != "" && !strings.HasPrefix(redirectURI, strings.TrimRight(l.settings.Issuer, "/")) {
		if client, found := l.clients[strings.ToLower(clientID)]; found && client.RedirectURIPattern != "" {
			if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
				htmlutil.Error(w, l.basePath, "post_logout_redirect_uri does not match Clients redirect URI pattern", http.StatusBadRequest)
				return
			}
		}
	}

	if client, found := l.clients[strings.ToLower(clientID)]; found && client.SessionName != "" {
		session, _ = l.sessionStore.Get(r, client.SessionName)
	}

	httputil.NoCache(w)

	if !session.IsNew {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			htmlutil.Error(w, l.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if redirectURI != "" {
		http.Redirect(w, r, redirectURI, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, "<!DOCTYPE html><meta charset=\"UTF-8\"><link rel=\"stylesheet\" href=\"%s/style.css\"><h1>Session terminated</h1>", l.basePath)
	}
}

func LogoutHandler(basePath string, settings *Settings, sessionStore sessions.Store, clients oauth2.Clients) http.Handler {
	return &logoutHandler{
		basePath:     basePath,
		settings:     settings,
		sessionStore: sessionStore,
		clients:      clients,
	}
}
