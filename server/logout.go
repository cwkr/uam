package server

import (
	"github.com/cwkr/auth-server/htmlutil"
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

	if redirectURI != "" {
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
	} else {
		redirectURI = l.settings.Issuer
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	if !session.IsNew {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func LogoutHandler(settings *Settings, sessionStore sessions.Store, clients oauth2.Clients) http.Handler {
	return &logoutHandler{
		settings:     settings,
		sessionStore: sessionStore,
		clients:      clients,
	}
}
