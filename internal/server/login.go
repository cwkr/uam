package server

import (
	_ "embed"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/cwkr/auth-server/internal/stringutil"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed templates/login.gohtml
var loginTpl string

func LoadLoginTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		loginTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type loginHandler struct {
	basePath    string
	peopleStore people.Store
	clients     oauth2.Clients
	issuer      string
	sessionName string
	tpl         *template.Template
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string

	var userID, password, clientID, sessionName string

	clientID = strings.ToLower(r.FormValue("client_id"))
	if clientID == "" {
		htmlutil.Error(w, j.basePath, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		sessionName = j.sessionName
		userID = strings.TrimSpace(r.PostFormValue("user_id"))
		if userID == "" {
			userID = strings.TrimSpace(r.PostFormValue("username"))
		}
		password = r.PostFormValue("password")
		if stringutil.IsAnyEmpty(userID, password) {
			message = "username and password must not be empty"
		} else {
			if client, clientExists := j.clients[clientID]; clientExists {
				if client.SessionName != "" {
					sessionName = client.SessionName
				}
			} else {
				htmlutil.Error(w, j.basePath, "invalid_client", http.StatusForbidden)
				return
			}

			if realUserID, err := j.peopleStore.Authenticate(userID, password); err == nil {
				if err := j.peopleStore.SaveSession(r, w, time.Now(), realUserID, sessionName); err != nil {
					htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("user_id=%s", realUserID)
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
	var err = j.tpl.ExecuteTemplate(w, "login", map[string]any{
		"base_path":      j.basePath,
		"issuer":         strings.TrimRight(j.issuer, "/"),
		"query":          template.HTML("?" + r.URL.RawQuery),
		"message":        message,
		"user_id":        userID,
		"password_empty": password == "",
	})
	if err != nil {
		htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(basePath string, peopleStore people.Store, clients oauth2.Clients, issuer, sessionName string) http.Handler {
	return &loginHandler{
		basePath:    basePath,
		peopleStore: peopleStore,
		clients:     clients,
		issuer:      issuer,
		sessionName: sessionName,
		tpl:         template.Must(template.New("login").Parse(loginTpl)),
	}
}
