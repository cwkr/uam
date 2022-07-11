package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/htmlutil"
	"github.com/cwkr/auth-server/store"
	"log"
	"net/http"
)

type meHandler struct {
	authenticator store.Authenticator
}

func (i *meHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var userID, user, active = i.authenticator.IsAuthenticated(r)

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "application/json")

	if active {
		var bytes, err = json.Marshal(struct {
			store.User
			UserID string `json:"user_id"`
		}{
			User:   user,
			UserID: userID,
		})
		if err == nil {
			w.Write(bytes)
		} else {
			htmlutil.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		htmlutil.Error(w, "not logged in", http.StatusForbidden)
	}
}

func MeHandler(authenticator store.Authenticator) http.Handler {
	return &meHandler{
		authenticator: authenticator,
	}
}
