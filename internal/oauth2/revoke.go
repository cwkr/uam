package oauth2

import (
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2/clients"
	"github.com/cwkr/auth-server/internal/oauth2/trl"
	"github.com/cwkr/auth-server/internal/stringutil"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"
)

type revokeHandler struct {
	tokenCreator TokenCreator
	trlStore     trl.Store
	clientStore  clients.Store
}

func (j *revokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodPost, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var (
		//timing                            = httputil.NewTiming()
		clientID, clientSecret, basicAuth = r.BasicAuth()
		token                             = strings.TrimSpace(r.PostFormValue("token"))
		tokenTypeHint                     = strings.TrimSpace(r.PostFormValue("token_type_hint"))
	)
	// when not using basic auth load client_id and client_secret parameters
	if !basicAuth {
		clientID = strings.TrimSpace(r.PostFormValue("client_id"))
		clientSecret = r.PostFormValue("client_secret")
	}

	// debug output of parameters
	log.Printf("client_id=%q client_secret=%q token_type_hint=%q token=%q",
		clientID, strings.Repeat("*", utf8.RuneCountInString(clientSecret)), tokenTypeHint, token)

	if clientSecret != "" {
		if _, err := j.clientStore.Authenticate(clientID, clientSecret); err != nil {
			Error(w, ErrorUnauthorizedClient, err.Error(), http.StatusUnauthorized)
			return
		}
	} else {
		if _, err := j.clientStore.Lookup(clientID); err != nil {
			Error(w, ErrorUnauthorizedClient, err.Error(), http.StatusUnauthorized)
			return
		}
	}

	if stringutil.IsAnyEmpty(clientID, token) {
		Error(w, ErrorInvalidRequest, "client_id and token parameters are required", http.StatusBadRequest)
		return
	}

	if claims, err := j.tokenCreator.Verify(token, ""); err == nil {
		if claims.TokenID == "" {
			Error(w, ErrorInvalidRequest, "token without id (jti)", http.StatusInternalServerError)
			return
		}
		if err := j.trlStore.Put(claims.TokenID, claims.Type, claims.Expiry.Time()); err != nil {
			Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("!!! %s", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func RevokeHandler(tokenCreator TokenCreator, clientStore clients.Store, trlStore trl.Store) http.Handler {
	return &revokeHandler{
		tokenCreator: tokenCreator,
		clientStore:  clientStore,
		trlStore:     trlStore,
	}
}
