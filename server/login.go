package server

import (
	_ "embed"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/httputil"
	"github.com/cwkr/auth-server/store"
	"github.com/cwkr/auth-server/stringutil"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	FieldUserID        = "user_id"
	FieldPasswordPlain = "password_plain"
)

//go:embed templates/login.gohtml
var loginTpl string

type loginHandler struct {
	settings      *Settings
	authenticator store.Authenticator
	sessionStore  sessions.Store
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string
	var session, _ = j.sessionStore.Get(r, j.settings.SessionID)
	var t, _ = template.New("login").Parse(loginTpl)

	var userID, password string

	if r.Method == http.MethodPost {
		userID = r.PostFormValue(FieldUserID)
		password = r.PostFormValue(FieldPasswordPlain)
		if stringutil.IsAnyEmpty(userID, password) {
			message = "Username and password must not be empty"
		} else {
			if user, authenticated := j.authenticator.Authenticate(userID, password); authenticated {
				session.Values["uid"] = userID
				session.Values["usr"] = user
				var now = time.Now()
				session.Values["sct"] = now
				if err := session.Save(r, w); err != nil {
					htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("userID = %s, user = %#v", userID, user)
				httputil.RedirectQuery(w, r, strings.TrimRight(j.settings.Issuer, "/")+"/auth", r.URL.Query())
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
		"issuer":  strings.TrimRight(j.settings.Issuer, "/"),
		"query":   template.HTML("?" + r.URL.RawQuery),
		"message": message,
		"userID":  userID,
		"title":   j.settings.Title,
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(settings *Settings, authenticator store.Authenticator, sessionStore sessions.Store) http.Handler {
	return &loginHandler{
		settings:      settings,
		authenticator: authenticator,
		sessionStore:  sessionStore,
	}
}