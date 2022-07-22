package server

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/oauth2/pkce"
	"github.com/cwkr/auth-server/people"
	"github.com/cwkr/auth-server/stringutil"
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
	authenticator people.Store
	publicKey     *rsa.PublicKey
	usePKCE       bool
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var t, _ = template.New("index").Parse(indexTpl)

	var pubASN1 = x509.MarshalPKCS1PublicKey(i.settings.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	var userID, active = i.authenticator.IsActiveSession(r)

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	var loginStart, loginExpiry string
	if iat, exp := i.authenticator.AuthenticationTime(r); active {
		loginStart = iat.Format(time.RFC3339)
		loginExpiry = exp.Format(time.RFC3339)
	}
	var codeVerifier = stringutil.RandomBytesString(10)
	var err = t.ExecuteTemplate(w, "index", map[string]any{
		"issuer":         strings.TrimRight(i.settings.Issuer, "/"),
		"public_key":     string(pubBytes),
		"state":          fmt.Sprint(rand.Int()),
		"scope":          i.settings.Scope,
		"clients":        i.settings.Clients,
		"title":          i.settings.Title,
		"user_id":        userID,
		"login_start":    loginStart,
		"login_expiry":   loginExpiry,
		"login_active":   active,
		"pkce":           i.usePKCE,
		"code_verifier":  codeVerifier,
		"code_challenge": pkce.CodeChallange(codeVerifier),
	})
	if err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(settings *Settings, authenticator people.Store, usePKCE bool) http.Handler {
	return &indexHandler{
		settings:      settings,
		authenticator: authenticator,
		usePKCE:       usePKCE,
	}
}
