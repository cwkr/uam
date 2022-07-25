package server

import (
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type logoutHandler struct {
	settings     *Settings
	sessionStore sessions.Store
	clients      oauth2.Clients
}

func (l *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		session, _  = l.sessionStore.Get(r, l.settings.SessionName)
		clientID    = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI = strings.TrimSpace(r.FormValue("redirect_uri"))
	)

	if redirectURI != "" && !strings.HasPrefix(redirectURI, strings.TrimRight(l.settings.Issuer, "/")) {
		if _, clientExists := l.clients[strings.ToLower(clientID)]; !clientExists {
			htmlutil.Error(w, "Redirect URI requires valid Client ID", http.StatusBadRequest)
			return
		}

		if client, found := l.clients[strings.ToLower(clientID)]; found && client.RedirectURIPattern != "" {
			if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
				htmlutil.Error(w, "Redirect URI does not match Clients redirect URI patterns", http.StatusBadRequest)
				return
			}
		}
	}

	httputil.NoCache(w)

	if !session.IsNew {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if redirectURI != "" {
		http.Redirect(w, r, redirectURI, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, "<!DOCTYPE html><link rel=\"stylesheet\" href=\"/style\"><h1>Session terminated</h1>")
	}
}

func LogoutHandler(settings *Settings, sessionStore sessions.Store, clients oauth2.Clients) http.Handler {
	return &logoutHandler{
		settings:     settings,
		sessionStore: sessionStore,
		clients:      clients,
	}
}
