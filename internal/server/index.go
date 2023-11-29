package server

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"github.com/cwkr/auth-server/internal/htmlutil"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2/pkce"
	"github.com/cwkr/auth-server/internal/stringutil"
	"github.com/cwkr/auth-server/settings"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"
)

//go:embed templates/index.gohtml
var indexTpl string

type indexHandler struct {
	basePath       string
	serverSettings *settings.Server
	publicKey      *rsa.PublicKey
	scope          string
	tpl            *template.Template
	version        string
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var pubASN1, _ = x509.MarshalPKIXPublicKey(i.serverSettings.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	httputil.NoCache(w)

	var title = strings.TrimSpace(i.serverSettings.Title)
	if title == "" {
		title = "Auth Server"
	}
	var codeVerifier = stringutil.RandomAlphanumericString(10)
	var err = i.tpl.ExecuteTemplate(w, "index", map[string]any{
		"base_path":      i.basePath,
		"issuer":         strings.TrimRight(i.serverSettings.Issuer, "/"),
		"title":          title,
		"public_key":     string(pubBytes),
		"state":          fmt.Sprint(rand.Int()),
		"nonce":          stringutil.RandomAlphanumericString(10),
		"scopes":         strings.Fields(i.scope),
		"code_verifier":  codeVerifier,
		"code_challenge": pkce.CodeChallange(codeVerifier),
		"version":        i.version,
	})
	if err != nil {
		htmlutil.Error(w, i.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(basePath string, serverSettings *settings.Server, scope, version string) http.Handler {
	return &indexHandler{
		basePath:       basePath,
		serverSettings: serverSettings,
		scope:          scope,
		tpl:            template.Must(template.New("index").Parse(indexTpl)),
		version:        version,
	}
}
