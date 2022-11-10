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
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"
)

//go:embed templates/index.gohtml
var indexTpl string

type indexHandler struct {
	basePath  string
	settings  *Settings
	publicKey *rsa.PublicKey
	scope     string
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var t, _ = template.New("index").Parse(indexTpl)

	var pubASN1, _ = x509.MarshalPKIXPublicKey(i.settings.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	httputil.NoCache(w)

	var codeVerifier = stringutil.RandomBytesString(10)
	var err = t.ExecuteTemplate(w, "index", map[string]any{
		"base_path":      i.basePath,
		"issuer":         strings.TrimRight(i.settings.Issuer, "/"),
		"public_key":     string(pubBytes),
		"state":          fmt.Sprint(rand.Int()),
		"nonce":          stringutil.RandomBytesString(10),
		"scope":          i.scope,
		"clients":        i.settings.Clients,
		"code_verifier":  codeVerifier,
		"code_challenge": pkce.CodeChallange(codeVerifier),
	})
	if err != nil {
		htmlutil.Error(w, i.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(basePath string, settings *Settings, scope string) http.Handler {
	return &indexHandler{
		basePath: basePath,
		settings: settings,
		scope:    scope,
	}
}
