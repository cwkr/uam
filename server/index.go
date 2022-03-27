package server

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"
)

//go:embed templates/index.gohtml
var indexTpl string

type indexHandler struct {
	settings     *Settings
	sessionStore sessions.Store
	publicKey    *rsa.PublicKey
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var t, _ = template.New("index").Parse(indexTpl)

	var pubASN1 = x509.MarshalPKCS1PublicKey(i.settings.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	var session, _ = i.sessionStore.Get(r, i.settings.SessionID)

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	var err = t.ExecuteTemplate(w, "index", map[string]interface{}{
		"issuer":     strings.TrimRight(i.settings.Issuer, "/"),
		"public_key": string(pubBytes),
		"state":      fmt.Sprint(rand.Int()),
		"clients":    i.settings.Clients,
		"title":      i.settings.Title,
		"user_id":    session.Values["user_id"],
		"user":       session.Values["user"],
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(settings *Settings, sessionStore sessions.Store) http.Handler {
	return &indexHandler{
		settings:     settings,
		sessionStore: sessionStore,
	}
}
