package server

import (
	_ "embed"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	FieldUserID   = "user_id"
	FieldPassword = "password"
)

//go:embed templates/login.gohtml
var loginTpl string

type loginHandler struct {
	settings     *Settings
	peopleStore  people.Store
	sessionStore sessions.Store
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string
	var session, _ = j.sessionStore.Get(r, j.settings.SessionName)
	var t, _ = template.New("login").Parse(loginTpl)

	var userID, password string

	if r.Method == http.MethodPost {
		userID = strings.TrimSpace(r.PostFormValue(FieldUserID))
		password = r.PostFormValue(FieldPassword)
		if stringutil.IsAnyEmpty(userID, password) {
			message = "username and password must not be empty"
		} else {
			if realUserID, err := j.peopleStore.Authenticate(userID, password); err == nil {
				session.Values["uid"] = realUserID
				var now = time.Now()
				session.Values["sct"] = now.Unix()
				if err := session.Save(r, w); err != nil {
					htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("userID=%s", realUserID)
				httputil.RedirectQuery(w, r, strings.TrimRight(j.settings.Issuer, "/")+"/authorize", r.URL.Query())
				return
			} else {
				message = err.Error()
			}
		}
	} else if r.Method == http.MethodGet {
		httputil.NoCache(w)
	}

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var err = t.ExecuteTemplate(w, "login", map[string]any{
		"issuer":  strings.TrimRight(j.settings.Issuer, "/"),
		"query":   template.HTML("?" + r.URL.RawQuery),
		"message": message,
		"userID":  userID,
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(settings *Settings, peopleStore people.Store, sessionStore sessions.Store) http.Handler {
	return &loginHandler{
		settings:     settings,
		peopleStore:  peopleStore,
		sessionStore: sessionStore,
	}
}
