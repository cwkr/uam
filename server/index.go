package server

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/userstore"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/index.gohtml
var indexTpl string

type indexHandler struct {
	settings      *Settings
	authenticator userstore.Authenticator
	publicKey     *rsa.PublicKey
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var t, _ = template.New("index").Parse(indexTpl)

	var pubASN1 = x509.MarshalPKCS1PublicKey(i.settings.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	var userID, user, active = i.authenticator.IsAuthenticated(r)

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	var loginStart, loginExpiry string
	if active {

	}
	if iat, exp := i.authenticator.AuthenticationTime(r); active {
		loginStart = iat.Format(time.RFC3339)
		loginExpiry = exp.Format(time.RFC3339)
	}
	var err = t.ExecuteTemplate(w, "index", map[string]interface{}{
		"issuer":       strings.TrimRight(i.settings.Issuer, "/"),
		"public_key":   string(pubBytes),
		"state":        fmt.Sprint(rand.Int()),
		"clients":      i.settings.Clients,
		"title":        i.settings.Title,
		"user_id":      userID,
		"user":         user,
		"login_start":  loginStart,
		"login_expiry": loginExpiry,
		"login_active": active,
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(settings *Settings, authenticator userstore.Authenticator) http.Handler {
	return &indexHandler{
		settings:      settings,
		authenticator: authenticator,
	}
}
