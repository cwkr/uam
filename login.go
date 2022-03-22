package main

import (
	_ "embed"
	"github.com/cwkr/auth-server/config"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"strings"
)

//go:embed templates/login.gohtml
var loginTpl string

type loginHandler struct {
	config        *config.Config
	authenticator oauth2.Authenticator
	sessionStore  sessions.Store
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string
	var session, _ = j.sessionStore.Get(r, cfg.SessionID)
	var t, _ = template.New("login").Parse(loginTpl)

	var userID, password string

	if r.Method == http.MethodPost {
		userID = r.PostFormValue("user_id")
		password = r.PostFormValue("password_plain")
		if oauth2.IsAnyEmpty(userID, password) {
			message = "Username and password must no be empty"
		} else {
			if _, authenticated := j.authenticator.Authenticate(userID, password); authenticated {
				session.Values["user_id"] = userID
				if err := session.Save(r, w); err != nil {
					htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				httputil.RedirectQuery(w, r, strings.TrimRight(cfg.Issuer, "/")+"/auth", r.URL.Query())
				return
			} else {
				message = "Invalid username and/or password"
			}
		}
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var err = t.ExecuteTemplate(w, "login", map[string]interface{}{
		"issuer":  strings.TrimRight(cfg.Issuer, "/"),
		"query":   template.HTML("?" + r.URL.RawQuery),
		"message": message,
		"userID":  userID,
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(cfg *config.Config, sessionStore sessions.Store) http.Handler {
	return &loginHandler{
		config:        cfg,
		authenticator: cfg,
		sessionStore:  sessionStore,
	}
}

func LogoutHandler(cfg *config.Config, sessionStore sessions.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var session, _ = sessionStore.Get(r, cfg.SessionID)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		if !session.IsNew {
			session.Options.MaxAge = -1
			if err := session.Save(r, w); err != nil {
				htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			htmlutil.Error(w, "Logged out", http.StatusOK)
		}
	})
}
