package oauth2

import (
	"encoding/json"
	"github.com/cwkr/auth-server/htmlutil"
	"log"
	"net/http"
	"strings"
)

type DiscoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
}

type discoveryDocumentHandler struct {
	issuer      string
	scope       string
	disablePKCE bool
}

func (d *discoveryDocumentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var baseURL = strings.TrimRight(d.issuer, "/")
	var discoveryDocument = DiscoveryDocument{
		Issuer:                            d.issuer,
		AuthorizationEndpoint:             baseURL + "/authorize",
		JwksURI:                           baseURL + "/jwks",
		ResponseTypesSupported:            []string{"code", "token"},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "refresh_token"},
		TokenEndpoint:                     baseURL + "/token",
		ScopesSupported:                   strings.Fields(d.scope),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
	}
	if !d.disablePKCE {
		discoveryDocument.CodeChallengeMethodsSupported = []string{"S256"}
	}
	if bytes, err := json.Marshal(discoveryDocument); err != nil {
		htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	}
}

func DiscoveryDocumentHandler(issuer, scope string, disablePKCE bool) http.Handler {
	return &discoveryDocumentHandler{
		issuer:      issuer,
		scope:       scope,
		disablePKCE: disablePKCE,
	}
}
