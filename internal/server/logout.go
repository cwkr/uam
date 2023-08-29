package server

import (
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2/clients"
	settings "github.com/cwkr/auth-server/settings"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type logoutHandler struct {
	basePath       string
	serverSettings *settings.Server
	sessionStore   sessions.Store
	clientStore    clients.Store
}

func (l *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		session, _  = l.sessionStore.Get(r, l.serverSettings.SessionName)
		clientID    = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI = strings.TrimSpace(r.FormValue("post_logout_redirect_uri"))
		idTokenHint = strings.TrimSpace(r.FormValue("id_token_hint"))
	)

	if idTokenHint != "" {
		if token, err := jwt.ParseSigned(idTokenHint); err == nil {
			var claims = jwt.Claims{}
			if err := token.UnsafeClaimsWithoutVerification(&claims); err == nil {
				if len([]string(claims.Audience)) > 1 && claims.Issuer == l.serverSettings.Issuer {
					clientID = claims.Audience[1]
				}
			}
		}
	}

	if clientID == "" {
		htmlutil.Error(w, l.basePath, "client_id or id_token_hint parameters are required", http.StatusBadRequest)
		return
	}

	var client clients.Client
	if c, err := l.clientStore.Lookup(clientID); err != nil {
		htmlutil.Error(w, l.basePath, "invalid_client", http.StatusForbidden)
		return
	} else {
		client = *c
	}

	if redirectURI != "" && !strings.HasPrefix(redirectURI, strings.TrimRight(l.serverSettings.Issuer, "/")) {
		if client.RedirectURIPattern != "" {
			if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
				htmlutil.Error(w, l.basePath, "post_logout_redirect_uri does not match Clients redirect URI pattern", http.StatusBadRequest)
				return
			}
		}
	}

	if client.SessionName != "" {
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

func LogoutHandler(basePath string, serverSettings *settings.Server, sessionStore sessions.Store, clientStore clients.Store) http.Handler {
	return &logoutHandler{
		basePath:       basePath,
		serverSettings: serverSettings,
		sessionStore:   sessionStore,
		clientStore:    clientStore,
	}
}
