package server

import (
	_ "embed"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
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
	peopleStore people.Store
	issuer      string
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string
	var t, _ = template.New("login").Parse(loginTpl)

	var userID, password string

	if r.Method == http.MethodPost {
		userID = strings.TrimSpace(r.PostFormValue(FieldUserID))
		password = r.PostFormValue(FieldPassword)
		if stringutil.IsAnyEmpty(userID, password) {
			message = "username and password must not be empty"
		} else {
			if realUserID, err := j.peopleStore.Authenticate(userID, password); err == nil {
				if err := j.peopleStore.SaveSession(r, w, realUserID, time.Now()); err != nil {
					htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("userID=%s", realUserID)
				httputil.RedirectQuery(w, r, strings.TrimRight(j.issuer, "/")+"/authorize", r.URL.Query())
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
		"issuer":  strings.TrimRight(j.issuer, "/"),
		"query":   template.HTML("?" + r.URL.RawQuery),
		"message": message,
		"userID":  userID,
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(peopleStore people.Store, issuer string) http.Handler {
	return &loginHandler{
		peopleStore: peopleStore,
		issuer:      issuer,
	}
}
