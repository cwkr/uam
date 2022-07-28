package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/internal/httputil"
	"github.com/cwkr/auth-server/internal/oauth2"
	"github.com/cwkr/auth-server/internal/people"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type peopleAPIHandler struct {
	peopleStore people.Store
}

func (p *peopleAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var userID = mux.Vars(r)["user_id"]
	if person, err := p.peopleStore.Lookup(userID); err == nil {
		var bytes, err = json.Marshal(person)
		if err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	} else {
		if err == people.ErrPersonNotFound {
			oauth2.Error(w, oauth2.ErrorNotFound, err.Error(), http.StatusNotFound)
		} else {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
		}
	}
}

func PeopleAPIHandler(peopleStore people.Store) http.Handler {
	return &peopleAPIHandler{
		peopleStore: peopleStore,
	}
}
