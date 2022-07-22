package server

import (
	"encoding/json"
	"github.com/cwkr/auth-server/oauth2"
	"github.com/cwkr/auth-server/people"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type peopleAPIHandler struct {
	peopleStore people.Store
}

func (p *peopleAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
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

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
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
